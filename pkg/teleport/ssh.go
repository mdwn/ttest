/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package teleport

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const (
	timeBetweenSSHConnectionChecks = 5 * time.Second
)

// sshClient is a
type sshClient struct {
	log    *logrus.Logger
	user   string
	signer ssh.Signer
}

func newSSHClient(cfg *config.Config) *sshClient {
	var sshSigner ssh.Signer
	var err error
	if len(cfg.ClusterConfig.PrivateKeyPassphrase) == 0 {
		sshSigner, err = ssh.ParsePrivateKey(cfg.ClusterConfig.GetPrivateKey())
	} else {
		sshSigner, err = ssh.ParsePrivateKeyWithPassphrase(cfg.ClusterConfig.GetPrivateKey(), []byte(cfg.ClusterConfig.PrivateKeyPassphrase))
	}
	if err != nil {
		cfg.Log.Debugf("Error using private key, attempting to move on. Error: %v", err)
	}

	return &sshClient{
		log:    cfg.Log,
		user:   cfg.ClusterConfig.ProvisionerConfig.User,
		signer: sshSigner,
	}
}

// waitForSSHConnection will wait for the SSH connection on a particular host.
func (s *sshClient) waitForSSHConnection(ctx context.Context, host string) error {
	ticker := time.NewTicker(timeBetweenSSHConnectionChecks)

	for {
		_, closer, err := s.createSession(ctx, host)
		closer()

		if err == nil {
			break
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return trace.Wrap(ctx.Err(), "timeout waiting for SSH session")
		}
	}

	return nil
}

// connectInteractive will start an interactive session with the host.
func (s *sshClient) connectInteractive(ctx context.Context, host string) error {
	session, closer, err := s.createSession(ctx, host)
	if err != nil {
		return trace.Wrap(err)
	}
	defer closer()

	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return trace.Wrap(err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return trace.BadParameter("this must be run from a terminal")
	}

	originalState, err := term.MakeRaw(fd)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		if err := term.Restore(fd, originalState); err != nil {
			s.log.Warnf("Error restoring original state: %v", err)
		}
	}()

	// Disable SSH echoing.
	modes := ssh.TerminalModes{}
	if err := session.RequestPty("xterm", height, width, modes); err != nil {
		return trace.Wrap(err, "error requesting pty")
	}

	if err := session.Shell(); err != nil {
		return trace.Wrap(err, "error starting shell")
	}

	return session.Wait()
}

// runUserCommand will run a command supplied by the user.
func (s *sshClient) runUserCommand(ctx context.Context, host string, command []string) error {
	session, closer, err := s.createSession(ctx, host)
	if err != nil {
		return trace.Wrap(err)
	}
	defer closer()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Run(strings.Join(command, " ")); err != nil {
		return err
	}

	return nil
}

// runCmd will run the given command on the host and return the output.
func (s *sshClient) runCmd(ctx context.Context, host, cmd string) (string, error) {
	session, closer, err := s.createSession(ctx, host)
	if err != nil {
		return "", trace.Wrap(err)
	}
	defer closer()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", trace.Wrap(err, string(output))
	}

	return string(output), err
}

// copyFilesToHost will copy the given local files to the host.
func (s *sshClient) copyFilesToHost(ctx context.Context, host, destination string, files ...string) error {
	session, closer, err := s.createSession(ctx, host)
	if err != nil {
		return trace.Wrap(err)
	}
	defer closer()

	pipe, err := session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	// Pipe a gzipped tarball into stdin on the SSH session.
	go func() {
		gzipWriter := gzip.NewWriter(pipe)
		tarWriter := tar.NewWriter(gzipWriter)

		defer func() {
			if err := tarWriter.Close(); err != nil {
				s.log.Errorf("error closing tar writer: %v", err)
			}
			if err := gzipWriter.Close(); err != nil {
				s.log.Errorf("error closing gzip writer: %v", err)
			}
			if err := pipe.Close(); err != nil {
				s.log.Errorf("error closing pipe writer: %v", err)
			}
		}()

		for _, fileName := range files {
			err := func() error {
				file, err := os.Open(fileName)
				if err != nil {
					return trace.Wrap(err)
				}
				defer func() {
					if err := file.Close(); err != nil {
						s.log.Errorf("error closing file: %v", err)
					}
				}()
				fileInfo, err := file.Stat()
				if err != nil {
					return trace.Wrap(err)
				}
				err = tarWriter.WriteHeader(&tar.Header{
					Typeflag: tar.TypeReg,
					Name:     fileInfo.Name(),
					Size:     fileInfo.Size(),
					Mode:     int64(fileInfo.Mode()),
				})
				if err != nil {
					return trace.Wrap(err)
				}
				s.log.Infof("Uploading file %s to %s", fileName, destination)
				_, err = io.Copy(tarWriter, file)
				if err != nil {
					s.log.Errorf("error uploading file: %v", err)
					return trace.Wrap(err)
				}
				return nil
			}()
			if err != nil {
				s.log.Errorf("error writing tar file: %v", err)
				return
			}
		}
	}()

	// Make sure the destination exists and untar the files into the directory.
	if err := session.Run(fmt.Sprintf("sudo mkdir -p %[1]s && sudo tar zxvf - -C %[1]s", destination)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// extractTarballOnHost will extract the given tarball on the host at the destination on the remote filesystem.
func (s *sshClient) extractTarballOnHost(ctx context.Context, host, destination, filename string) error {
	session, closer, err := s.createSession(ctx, host)
	if err != nil {
		return trace.Wrap(err)
	}
	defer closer()

	pipe, err := session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	// Pipe a gzipped tarball into stdin on the SSH session.
	go func() {
		defer func() {
			if err := pipe.Close(); err != nil {
				s.log.Errorf("error closing pipe writer: %v", err)
			}
		}()

		file, err := os.Open(filename)
		if err != nil {
			s.log.Errorf("error opening file: %v", err)
			return
		}
		defer func() {
			if err := file.Close(); err != nil {
				s.log.Errorf("error closing file: %v", err)
			}
		}()

		_, err = io.Copy(pipe, file)
		if err != nil {
			s.log.Errorf("error copying response body: %v", err)
		}
	}()

	// Make sure the destination exists and untar the files into the directory.
	if err := session.Run(fmt.Sprintf("sudo mkdir -p %[1]s && sudo tar zxf - -C %[1]s", destination)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// createFile will create a file with the given file contents on the remote host.
func (s *sshClient) createFile(ctx context.Context, host, fileName string, fileContents io.Reader) error {
	session, closer, err := s.createSession(ctx, host)
	if err != nil {
		return trace.Wrap(err)
	}
	defer closer()

	pipe, err := session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	go func() {
		defer pipe.Close()
		_, err := io.Copy(pipe, fileContents)
		if err != nil {
			s.log.Errorf("error copying base config: %v", err)
		}
	}()

	return trace.Wrap(session.Run(fmt.Sprintf(`cat - | sudo tee "%s"`, fileName)))
}

// clientConfig returns the SSH client config.
func (s *sshClient) clientConfig(agentClient agent.ExtendedAgent) *ssh.ClientConfig {
	var authMethods []ssh.AuthMethod
	if agentClient == nil {
		authMethods = append(authMethods, ssh.PublicKeys(s.signer))
	} else {
		authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
	}

	return &ssh.ClientConfig{
		User:            s.user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// createSession creates an SSH session along with a closer function.
func (s *sshClient) createSession(ctx context.Context, host string) (*ssh.Session, func(), error) {
	var session *ssh.Session
	var conn net.Conn
	var client *ssh.Client
	var agentClient agent.ExtendedAgent

	// Connect to the SSH agent client if possible
	socket := os.Getenv("SSH_AUTH_SOCK")
	agentConn, err := net.Dial("unix", socket)
	if err != nil {
		s.log.Errorf("unable to connect to the SSH agent")
	} else {
		agentClient = agent.NewClient(agentConn)
		_, err := agentClient.Signers()
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
	}

	closer := func() {
		if session != nil {
			if err := session.Close(); err != nil {
				s.log.Debugf("error closing the session: %v", err)
			}
		}

		if err := client.Close(); err != nil {
			s.log.Debugf("error closing the SSH client: %v", err)
		}

		if err := conn.Close(); err != nil {
			s.log.Debugf("error closing the connection: %v", err)
		}

		if err := agentConn.Close(); err != nil {
			s.log.Debugf("error closing the agent connection: %v", err)
		}
	}

	if s.signer == nil && agentClient == nil {
		closer()
		return nil, nil, trace.BadParameter("could not connect to the agent and couldn't use a private key")
	}

	dialer := net.Dialer{}
	addr := fmt.Sprintf("%s:%d", host, 22)
	conn, err = dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		closer()
		return nil, nil, trace.Wrap(err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, s.clientConfig(agentClient))
	if err != nil {
		closer()
		return nil, nil, trace.Wrap(err)
	}

	client = ssh.NewClient(sshConn, chans, reqs)

	session, err = client.NewSession()
	if err != nil {
		closer()
		return nil, nil, trace.Wrap(err)
	}

	return session, closer, nil
}
