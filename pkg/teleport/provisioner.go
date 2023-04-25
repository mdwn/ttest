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
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gravitational/trace"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/mdwn/ttest/pkg/provider"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	tarballDownloadCacheSuffix = "teleport-tars"
	ttlUntilTeleportStarts     = 10 * time.Second
	ttlForSSHConnections       = 5 * time.Minute
	letsEncryptURI             = "https://acme-v02.api.letsencrypt.org/directory"
	nodeSetupTimeout           = 5 * time.Minute
	serverName                 = "server"
)

// configTemplate will be used when rendering Teleport YAML templates.
type configTemplate struct {
	ClusterName      string
	ProxyFQDN        string
	LetsEncryptEmail string
	LetsEncryptURI   string
	LicenseFile      string
	InviteToken      string
	CAPin            string
}

// provisionStep is an individual step for a provisioning operation.
type provisionStep func(context.Context) error

// Provisioner will install, set up, and configure Teleport on a host.
type Provisioner struct {
	log            *logrus.Logger
	user           string
	clusterName    string
	leEmail        string
	ssh            *sshClient
	provider       provider.Provider
	downloadCache  string
	teleportTarURL string
	builder        *Builder
	license        []byte

	serverConfig string
	nodeConfigs  map[string]config.NodeRolesAndConfig
}

// NewProvisioner creates a new Teleport provisioner.
func NewProvisioner(ctx context.Context, cfg *config.Config) (*Provisioner, error) {
	provider, err := provider.Get(ctx, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	builder, err := NewBuilder(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &Provisioner{
		log:            cfg.Log,
		user:           cfg.ClusterConfig.ProvisionerConfig.User,
		clusterName:    cfg.ClusterName,
		leEmail:        cfg.ClusterConfig.LetsEncryptEmail,
		ssh:            newSSHClient(cfg),
		provider:       provider,
		downloadCache:  path.Join(cfg.ClusterConfig.StoreDir, tarballDownloadCacheSuffix),
		teleportTarURL: cfg.ClusterConfig.ProvisionerConfig.TeleportTarURL,
		builder:        builder,
		license:        cfg.ClusterConfig.GetLicense(),
		serverConfig:   cfg.ClusterConfig.ServerConfig,
		nodeConfigs:    cfg.ClusterConfig.NodeConfigs,
	}, nil
}

// Create will create infrastructure and install and configure Teleport on the nodes.
func (p *Provisioner) Create(ctx context.Context) error {
	return trace.Wrap(p.runSteps(
		ctx,
		p.createInfrastructure,
		p.waitForSSHConnections,
		p.deployBinaries,
		p.configureAndStart,
	))
}

// Deploy will install and configure Teleport on the nodes.
func (p *Provisioner) Deploy(ctx context.Context) error {
	return trace.Wrap(p.runSteps(
		ctx,
		p.waitForSSHConnections,
		p.deployBinaries,
		p.configureAndStart,
	))
}

// Destroy will destroy the underlying infrastructure.
func (p *Provisioner) Destroy(ctx context.Context) error {
	return trace.Wrap(p.runSteps(
		ctx,
		p.destroyInfrastructure,
	))
}

// NodeInfo contains information about the node.
type NodeInfo struct {
	Host   string
	Roles  []string
	Config string
}

// Nodes will create a mapping of names to hosts.
func (p *Provisioner) Nodes(ctx context.Context) (map[string]NodeInfo, error) {
	serverHost, err := p.provider.ServerHost(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	nodes, err := p.provider.Nodes(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	numNodes := len(nodes)

	nodeMap := map[string]NodeInfo{
		serverName: {
			Host:   serverHost,
			Config: p.serverConfig,
		},
	}

	// Sort the list of node names. These will correspond to each node returned from the provider.
	nodeNames := make([]string, 0, numNodes)
	for name := range p.nodeConfigs {
		nodeNames = append(nodeNames, name)
	}
	sort.Strings(nodeNames)

	for i, nodeName := range nodeNames {
		var host string
		if i < numNodes {
			host = nodes[i]
		}
		nodeMap[nodeName] = NodeInfo{
			Host:   host,
			Roles:  p.nodeConfigs[nodeName].Roles,
			Config: p.nodeConfigs[nodeName].Config,
		}
	}

	return nodeMap, nil
}

// SSH will allow an interactive SSH session to a node.
func (p *Provisioner) SSH(ctx context.Context, nodeName string, command ...string) error {
	nodes, err := p.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	node, ok := nodes[nodeName]
	if !ok {
		return trace.NotFound("unable to find node name %s in list of nodes", nodeName)
	}

	if node.Host == "" {
		return trace.NotFound("no host assigned to node %s", nodeName)
	}

	if len(command) > 0 {
		return p.ssh.runUserCommand(ctx, node.Host, command)
	}

	return p.ssh.connectInteractive(ctx, node.Host)
}

// TCTL will allow an arbitrary tctl command on the cluster.
func (p *Provisioner) TCTL(ctx context.Context, command ...string) error {
	serverHost, err := p.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err, "unable to find get server")
	}

	tctl := newTCTLClient(p.log, p.ssh, serverHost)
	return tctl.runCommand(ctx, command)
}

// createInfrastructure will create the infrastructure.
func (p *Provisioner) createInfrastructure(ctx context.Context) error {
	p.log.Infof("Creating the infrastructure.")
	return trace.Wrap(p.provider.Create(ctx))
}

// waitForSSHConnections will wait for all SSH connections.
func (p *Provisioner) waitForSSHConnections(ctx context.Context) error {
	p.log.Infof("Waiting for SSH connections to start.")

	serverHost, err := p.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	nodes, err := p.provider.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	allHosts := append([]string{serverHost}, nodes...)

	errs := make(chan error, len(allHosts))

	sshTimeoutCtx, cancel := context.WithTimeout(ctx, ttlForSSHConnections)
	defer cancel()
	var wg sync.WaitGroup
	for _, host := range allHosts {
		hostCopy := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- p.ssh.waitForSSHConnection(sshTimeoutCtx, hostCopy)
		}()
	}

	wg.Wait()
	close(errs)

	return trace.NewAggregateFromChannel(errs, ctx)
}

// deployBinaries will deploy Teleport binaries to the nodes.
func (p *Provisioner) deployBinaries(ctx context.Context) error {
	p.log.Infof("Deploying Teleport.")

	var binaries []string
	var teleportTarFile string
	var err error
	if p.teleportTarURL == "" {
		binaries, err = p.builder.Build()
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		teleportTarFile, err = p.downloadFileToCache(ctx, p.teleportTarURL)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	serverHost, err := p.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	nodes, err := p.provider.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	allHosts := append([]string{serverHost}, nodes...)

	// Copy binaries to all hosts.
	for _, host := range allHosts {
		p.log.Infof("Copying Teleport binaries to %s", host)
		// Stop the Teleport service if it exists.
		if err := p.stopService(ctx, host); err != nil {
			return trace.Wrap(err, "error stopping Teleport service on %s", host)
		}

		if teleportTarFile == "" {
			// Copy the built binaries to the host.
			err = p.copyTeleportBinariesToHost(ctx, host, binaries...)
			if err != nil {
				return trace.Wrap(err, "error copying Teleport binaries to %s", host)
			}
		} else {
			// Copy the downloaded binaries to the host.
			if err := p.ssh.extractTarballOnHost(ctx, host, "/opt", teleportTarFile); err != nil {
				return trace.Wrap(err, "error extracting Teleport binaries on %s", host)
			}
		}

		// Make sure Teleport binaries are on path.
		err = p.addTeleportToPath(ctx, host)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// configureAndStart will configure the nodes and start the services.
func (p *Provisioner) configureAndStart(ctx context.Context) error {
	p.log.Infof("Configuring and starting Teleport.")
	serverHost, err := p.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	proxyFQDN, err := p.provider.ProxyFQDN(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	serverSetupCtx, cancel := context.WithTimeout(ctx, nodeSetupTimeout)
	// Set up the server.
	err = p.setupServerConfig(serverSetupCtx, serverHost, proxyFQDN, p.license)
	if err != nil {
		return trace.Wrap(err, "error setting up server config")
	}

	err = p.setupService(serverSetupCtx, serverHost)
	if err != nil {
		return trace.Wrap(err)
	}

	tctl := newTCTLClient(p.log, p.ssh, serverHost)

	if err := tctl.waitForStart(serverSetupCtx, ttlUntilTeleportStarts); err != nil {
		return trace.Wrap(err, "timeout waiting for Teleport service to start on server")
	}

	// We're done with the server setup ctx.
	cancel()

	// Get the nodes from the provider.
	nodes, err := p.provider.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Get the CA pin to be used in later nodes.
	caPin, err := tctl.caPin(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	numNodes := len(p.nodeConfigs)
	if numNodes != len(nodes) {
		return trace.BadParameter("number of nodes from provider (%d) does not match the provided node configs (%d)", len(nodes), numNodes)
	}

	nodeConfigs, err := p.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err, "error getting nodes mapped to their configs")
	}
	nodeSetupCtx, cancel := context.WithTimeout(ctx, nodeSetupTimeout)

	errs := make(chan error, numNodes)

	nodeStarted := make(chan struct{})
	for nn, i := range nodeConfigs {
		// Skip the server as it has already been setup.
		if nn == serverName {
			continue
		}
		nodeName := nn
		nodeInfo := i
		go func() {
			defer func() { nodeStarted <- struct{}{} }()

			p.log.Infof("Setting up config for node %s with roles %s", nodeName, strings.Join(nodeInfo.Roles, ","))
			inviteToken, err := tctl.inviteToken(nodeSetupCtx, nodeInfo.Roles)
			if err != nil {
				errs <- trace.Wrap(err, "error getting invite token for node %s", nodeName)
				return
			}

			if err := p.setupNodeConfig(nodeSetupCtx, nodeInfo.Host, proxyFQDN, inviteToken, caPin, nodeInfo.Config); err != nil {
				errs <- trace.Wrap(err, "error setting up node config for node %s", nodeName)
				return
			}

			err = p.setupService(nodeSetupCtx, nodeInfo.Host)
			if err != nil {
				errs <- trace.Wrap(err, "error setting up service for node %s", nodeName)
				return
			}
			p.log.Infof("Successfully setup node config for %s", nodeName)
		}()
	}

	nodesFinished := 0
	for {
		<-nodeStarted
		nodesFinished++
		if nodesFinished == numNodes {
			break
		}
	}
	cancel()

	close(errs)

	return trace.NewAggregateFromChannel(errs, ctx)
}

// destroyInfrastructure will destroy the infrastructure.
func (p *Provisioner) destroyInfrastructure(ctx context.Context) error {
	p.log.Infof("Destroying the infrastructure.")
	return trace.Wrap(p.provider.Destroy(ctx))
}

// runSteps will run the individual steps.
func (p *Provisioner) runSteps(ctx context.Context, steps ...provisionStep) error {
	for _, stepFn := range steps {
		if err := stepFn(ctx); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// copyTeleportBinariesToHost will copy the given files to the host.
func (p *Provisioner) copyTeleportBinariesToHost(ctx context.Context, host string, files ...string) error {
	return p.ssh.copyFilesToHost(ctx, host, "/opt/teleport", files...)
}

// stopService will stop the Teleport service if it's running.
func (p *Provisioner) stopService(ctx context.Context, host string) error {
	_, err := p.ssh.runCmd(ctx, host, `sudo systemctl stop teleport`)

	// Ignore an exit error, as the service may not yet exist.
	if _, ok := trace.Unwrap(err).(*ssh.ExitError); err != nil && !ok {
		return trace.Wrap(err)
	}
	return nil
}

// downloadFileToCache will download the file to the download cache and return its location.
func (p *Provisioner) downloadFileToCache(ctx context.Context, url string) (string, error) {
	filename := path.Base(p.teleportTarURL)
	destination := path.Join(p.downloadCache, filename)

	// Only download the file if we need to.
	if _, err := os.Stat(destination); err == nil {
		p.log.Infof("%s already in the cache, skipping download", filename)
		return destination, nil
	}

	p.log.Infof("Downloading %s", url)

	// Make sure the destination directory exists
	if err := os.MkdirAll(path.Dir(destination), 0o755); err != nil {
		return "", trace.Wrap(err)
	}

	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", trace.Wrap(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			p.log.Errorf("error closing destination file: %v", err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", trace.Wrap(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", trace.Wrap(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.log.Errorf("error closing response body: %v", err)
		}
	}()

	_, copyErr := io.Copy(file, resp.Body)
	if copyErr != nil {
		p.log.Infof("Download failed, removing the file from the download cache")
		if err := os.Remove(destination); err != nil {
			return "", trace.NewAggregate(copyErr, err)
		}
		return "", trace.Wrap(copyErr)
	}
	return destination, nil
}

// setupServerConfig will install the config on the server.
func (p *Provisioner) setupServerConfig(ctx context.Context, host, proxyFQDN string, license []byte) error {
	var licenseFile string
	if len(p.license) > 0 {
		licenseFile = "/etc/teleport-license.pem"
	}
	buf := bytes.NewBuffer([]byte{})

	serverConf, err := template.New("serverConfig").Parse(p.serverConfig)
	if err != nil {
		return trace.Wrap(err)
	}

	err = serverConf.Execute(buf, configTemplate{
		ClusterName:      p.clusterName,
		ProxyFQDN:        proxyFQDN,
		LetsEncryptEmail: p.leEmail,
		LetsEncryptURI:   letsEncryptURI,
		LicenseFile:      licenseFile,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	err = p.ssh.createFile(ctx, host, "/etc/teleport.yaml", buf)
	if err != nil {
		return trace.Wrap(err)
	}

	if licenseFile != "" {
		buf = bytes.NewBuffer(license)

		err = p.ssh.createFile(ctx, host, "/etc/teleport-license.pem", buf)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// setupNodeConfig will install the config on the given node.
func (p *Provisioner) setupNodeConfig(ctx context.Context, host, proxyFQDN, inviteToken, caPin, nodeConfig string) error {
	buf := bytes.NewBuffer([]byte{})
	nodeConf, err := template.New("nodeConfig").Parse(nodeConfig)
	if err != nil {
		return trace.Wrap(err)
	}

	err = nodeConf.Execute(buf, configTemplate{
		ClusterName:      p.clusterName,
		ProxyFQDN:        proxyFQDN,
		LetsEncryptEmail: p.leEmail,
		LetsEncryptURI:   letsEncryptURI,
		InviteToken:      inviteToken,
		CAPin:            caPin,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	err = p.ssh.createFile(ctx, host, "/etc/teleport.yaml", buf)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// addTeleportToPath will add the Teleport binaries to the path.
func (p *Provisioner) addTeleportToPath(ctx context.Context, host string) error {
	_, err := p.ssh.runCmd(ctx, host, `echo 'export PATH="/opt/teleport-ent:/opt/teleport:$PATH"' | sudo tee "/etc/profile.d/teleport-bin.sh"`)
	if err != nil {
		return trace.Wrap(err)
	}

	p.log.Infof("Teleport has been added to the path on host %s", host)

	return nil
}

// setupService will set up and start the Teleport systemd service.
func (p *Provisioner) setupService(ctx context.Context, host string) error {
	if err := p.setupSystemd(ctx, host); err != nil {
		return trace.Wrap(err)
	}

	if err := p.enableAndStart(ctx, host); err != nil {
		return trace.Wrap(err)
	}

	p.log.Infof("Teleport has been enabled in systemd and started on %s", host)

	return nil
}

// setupSystemd will set up the Teleport systemd entry on the host.
func (p *Provisioner) setupSystemd(ctx context.Context, host string) error {
	_, err := p.ssh.runCmd(ctx, host, `sudo -i teleport install systemd | sudo tee /etc/systemd/system/teleport.service`)
	return trace.Wrap(err)
}

// enableAndStart will enable the Teleport service on the host.
func (p *Provisioner) enableAndStart(ctx context.Context, host string) error {
	_, err := p.ssh.runCmd(ctx, host, `sudo systemctl enable teleport && sudo systemctl start teleport`)
	return trace.Wrap(err)
}
