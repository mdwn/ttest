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
	_ "embed"
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

// trustedClusterTemplate is a template for creating trusted cluster objects on
// leaf nodes.
//
//go:embed assets/trustedcluster.yaml.tpl
var trustedClusterTemplate string

// visitorRole is a role for setting up a visitor role on a leaf cluster. It's used
// for setting up trusted clusters.
//
//go:embed assets/visitorrole.yaml
var visitorRole string

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

// Cluster will install, set up, and configure Teleport on a host.
type Cluster struct {
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

// NewCluster creates a new Teleport cluster that can provision and interact with the cluster.
func NewCluster(ctx context.Context, cfg *config.Config) (*Cluster, error) {
	provider, err := provider.Get(ctx, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	builder, err := NewBuilder(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &Cluster{
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
func (c *Cluster) Create(ctx context.Context) error {
	return trace.Wrap(c.runSteps(
		ctx,
		c.createInfrastructure,
		c.waitForSSHConnections,
		c.deployBinaries,
		c.configureAndStart,
	))
}

// Deploy will install and configure Teleport on the nodes.
func (c *Cluster) Deploy(ctx context.Context) error {
	return trace.Wrap(c.runSteps(
		ctx,
		c.waitForSSHConnections,
		c.deployBinaries,
		c.configureAndStart,
	))
}

// Destroy will destroy the underlying infrastructure.
func (c *Cluster) Destroy(ctx context.Context) error {
	return trace.Wrap(c.runSteps(
		ctx,
		c.destroyInfrastructure,
	))
}

// NodeInfo contains information about the node.
type NodeInfo struct {
	Host   string
	Roles  []string
	Config string
}

// Nodes will create a mapping of names to hosts.
func (c *Cluster) Nodes(ctx context.Context) (map[string]NodeInfo, error) {
	serverHost, err := c.provider.ServerHost(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	nodes, err := c.provider.Nodes(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	numNodes := len(nodes)

	nodeMap := map[string]NodeInfo{
		serverName: {
			Host:   serverHost,
			Config: c.serverConfig,
		},
	}

	// Sort the list of node names. These will correspond to each node returned from the provider.
	nodeNames := make([]string, 0, numNodes)
	for name := range c.nodeConfigs {
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
			Roles:  c.nodeConfigs[nodeName].Roles,
			Config: c.nodeConfigs[nodeName].Config,
		}
	}

	return nodeMap, nil
}

// SSH will allow an interactive SSH session to a node.
func (c *Cluster) SSH(ctx context.Context, nodeName string, command ...string) error {
	nodes, err := c.Nodes(ctx)
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
		return c.ssh.runUserCommand(ctx, node.Host, command)
	}

	return c.ssh.connectInteractive(ctx, node.Host)
}

// TCTL will allow an arbitrary tctl command on the cluster.
func (c *Cluster) TCTL(ctx context.Context, command ...string) error {
	serverHost, err := c.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err, "unable to get server")
	}

	tctl := newTCTLClient(c.log, c.ssh, serverHost)
	return tctl.runCommand(ctx, command)
}

// Trust will set up a trust relationship with the given provisioner.
func (c *Cluster) Trust(ctx context.Context, root *Cluster) error {
	leafServerHost, err := c.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err, "unable to get leaf server host")
	}

	rootServerHost, err := root.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err, "unable to get root server host")
	}
	rootProxyFQDN, err := root.provider.ProxyFQDN(ctx)
	if err != nil {
		return trace.Wrap(err, "unable to get root proxy FQDN")
	}

	c.log.Infof("Creating visitor role on leaf cluster %s", c.clusterName)
	leafTCTL := newTCTLClient(c.log, c.ssh, leafServerHost)
	if err := leafTCTL.create(ctx, visitorRole, true); err != nil {
		return trace.Wrap(err)
	}

	c.log.Infof("Creating trusted cluster token on cluster %s", root.clusterName)
	rootTCTL := newTCTLClient(root.log, root.ssh, rootServerHost)
	trustedToken, err := rootTCTL.trustedClusterToken(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	template, err := template.New("trusted-cluster-template").Parse(trustedClusterTemplate)
	if err != nil {
		return trace.Wrap(err)
	}

	trustedCluster := bytes.NewBuffer(nil)
	err = template.Execute(trustedCluster, struct {
		RootClusterName     string
		TrustedClusterToken string
		RootProxyFQDN       string
	}{
		RootClusterName:     root.clusterName,
		TrustedClusterToken: trustedToken,
		RootProxyFQDN:       rootProxyFQDN,
	})
	if err != nil {
		return trace.Wrap(err, "unable to create trusted cluster object")
	}

	c.log.Infof("Creating trusted cluster object on leaf cluster %s", c.clusterName)
	if err := leafTCTL.create(ctx, trustedCluster.String(), false); err != nil {
		return trace.Wrap(err, "error creating trusted cluster in leaf")
	}

	c.log.Infof("Trust relationship established!")

	return nil
}

// createInfrastructure will create the infrastructure.
func (c *Cluster) createInfrastructure(ctx context.Context) error {
	c.log.Infof("Creating the infrastructure.")
	return trace.Wrap(c.provider.Create(ctx))
}

// waitForSSHConnections will wait for all SSH connections.
func (c *Cluster) waitForSSHConnections(ctx context.Context) error {
	c.log.Infof("Waiting for SSH connections to start.")

	serverHost, err := c.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	nodes, err := c.provider.Nodes(ctx)
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
			errs <- c.ssh.waitForSSHConnection(sshTimeoutCtx, hostCopy)
		}()
	}

	wg.Wait()
	close(errs)

	return trace.NewAggregateFromChannel(errs, ctx)
}

// deployBinaries will deploy Teleport binaries to the nodes.
func (c *Cluster) deployBinaries(ctx context.Context) error {
	c.log.Infof("Deploying Teleport.")

	var binaries []string
	var teleportTarFile string
	var err error
	if c.teleportTarURL == "" {
		binaries, err = c.builder.Build()
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		teleportTarFile, err = c.downloadFileToCache(ctx, c.teleportTarURL)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	serverHost, err := c.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	nodes, err := c.provider.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	allHosts := append([]string{serverHost}, nodes...)

	// Copy binaries to all hosts.
	for _, host := range allHosts {
		c.log.Infof("Copying Teleport binaries to %s", host)
		// Stop the Teleport service if it exists.
		if err := c.stopService(ctx, host); err != nil {
			return trace.Wrap(err, "error stopping Teleport service on %s", host)
		}

		if teleportTarFile == "" {
			// Copy the built binaries to the host.
			err = c.copyTeleportBinariesToHost(ctx, host, binaries...)
			if err != nil {
				return trace.Wrap(err, "error copying Teleport binaries to %s", host)
			}
		} else {
			// Copy the downloaded binaries to the host.
			if err := c.ssh.extractTarballOnHost(ctx, host, "/opt", teleportTarFile); err != nil {
				return trace.Wrap(err, "error extracting Teleport binaries on %s", host)
			}
		}

		// Make sure Teleport binaries are on path.
		err = c.addTeleportToPath(ctx, host)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// configureAndStart will configure the nodes and start the services.
func (c *Cluster) configureAndStart(ctx context.Context) error {
	c.log.Infof("Configuring and starting Teleport.")
	serverHost, err := c.provider.ServerHost(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	proxyFQDN, err := c.provider.ProxyFQDN(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	serverSetupCtx, cancel := context.WithTimeout(ctx, nodeSetupTimeout)
	// Set up the server.
	err = c.setupServerConfig(serverSetupCtx, serverHost, proxyFQDN, c.license)
	if err != nil {
		return trace.Wrap(err, "error setting up server config")
	}

	err = c.setupService(serverSetupCtx, serverHost)
	if err != nil {
		return trace.Wrap(err)
	}

	tctl := newTCTLClient(c.log, c.ssh, serverHost)

	if err := tctl.waitForStart(serverSetupCtx, ttlUntilTeleportStarts); err != nil {
		return trace.Wrap(err, "timeout waiting for Teleport service to start on server")
	}

	// We're done with the server setup ctx.
	cancel()

	// Get the nodes from the provider.
	nodes, err := c.provider.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Get the CA pin to be used in later nodes.
	caPin, err := tctl.caPin(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	numNodes := len(c.nodeConfigs)
	if numNodes != len(nodes) {
		return trace.BadParameter("number of nodes from provider (%d) does not match the provided node configs (%d)", len(nodes), numNodes)
	}

	nodeConfigs, err := c.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err, "error getting nodes mapped to their configs")
	}
	nodeSetupCtx, cancel := context.WithTimeout(ctx, nodeSetupTimeout)

	errs := make(chan error, numNodes)

	nodeStarted := make(chan struct{})
	for nn, i := range nodeConfigs {
		// Skip the server as it has already been setuc.
		if nn == serverName {
			continue
		}
		nodeName := nn
		nodeInfo := i
		go func() {
			defer func() { nodeStarted <- struct{}{} }()

			c.log.Infof("Setting up config for node %s with roles %s", nodeName, strings.Join(nodeInfo.Roles, ","))
			inviteToken, err := tctl.inviteToken(nodeSetupCtx, nodeInfo.Roles)
			if err != nil {
				errs <- trace.Wrap(err, "error getting invite token for node %s", nodeName)
				return
			}

			if err := c.setupNodeConfig(nodeSetupCtx, nodeInfo.Host, proxyFQDN, inviteToken, caPin, nodeInfo.Config); err != nil {
				errs <- trace.Wrap(err, "error setting up node config for node %s", nodeName)
				return
			}

			err = c.setupService(nodeSetupCtx, nodeInfo.Host)
			if err != nil {
				errs <- trace.Wrap(err, "error setting up service for node %s", nodeName)
				return
			}
			c.log.Infof("Successfully setup node config for %s", nodeName)
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
func (c *Cluster) destroyInfrastructure(ctx context.Context) error {
	c.log.Infof("Destroying the infrastructure.")
	return trace.Wrap(c.provider.Destroy(ctx))
}

// runSteps will run the individual steps.
func (c *Cluster) runSteps(ctx context.Context, steps ...provisionStep) error {
	for _, stepFn := range steps {
		if err := stepFn(ctx); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// copyTeleportBinariesToHost will copy the given files to the host.
func (c *Cluster) copyTeleportBinariesToHost(ctx context.Context, host string, files ...string) error {
	return c.ssh.copyFilesToHost(ctx, host, "/opt/teleport", files...)
}

// stopService will stop the Teleport service if it's running.
func (c *Cluster) stopService(ctx context.Context, host string) error {
	_, err := c.ssh.runCmd(ctx, host, `sudo systemctl stop teleport`)

	// Ignore an exit error, as the service may not yet exist.
	if _, ok := trace.Unwrap(err).(*ssh.ExitError); err != nil && !ok {
		return trace.Wrap(err)
	}
	return nil
}

// downloadFileToCache will download the file to the download cache and return its location.
func (c *Cluster) downloadFileToCache(ctx context.Context, url string) (string, error) {
	filename := path.Base(c.teleportTarURL)
	destination := path.Join(c.downloadCache, filename)

	// Only download the file if we need to.
	if _, err := os.Stat(destination); err == nil {
		c.log.Infof("%s already in the cache, skipping download", filename)
		return destination, nil
	}

	c.log.Infof("Downloading %s", url)

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
			c.log.Errorf("error closing destination file: %v", err)
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
			c.log.Errorf("error closing response body: %v", err)
		}
	}()

	_, copyErr := io.Copy(file, resp.Body)
	if copyErr != nil {
		c.log.Infof("Download failed, removing the file from the download cache")
		if err := os.Remove(destination); err != nil {
			return "", trace.NewAggregate(copyErr, err)
		}
		return "", trace.Wrap(copyErr)
	}
	return destination, nil
}

// setupServerConfig will install the config on the server.
func (c *Cluster) setupServerConfig(ctx context.Context, host, proxyFQDN string, license []byte) error {
	var licenseFile string
	if len(c.license) > 0 {
		licenseFile = "/etc/teleport-license.pem"
	}
	buf := bytes.NewBuffer([]byte{})

	serverConf, err := template.New("serverConfig").Parse(c.serverConfig)
	if err != nil {
		return trace.Wrap(err)
	}

	err = serverConf.Execute(buf, configTemplate{
		ClusterName:      c.clusterName,
		ProxyFQDN:        proxyFQDN,
		LetsEncryptEmail: c.leEmail,
		LetsEncryptURI:   letsEncryptURI,
		LicenseFile:      licenseFile,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	err = c.ssh.createFile(ctx, host, "/etc/teleport.yaml", buf)
	if err != nil {
		return trace.Wrap(err)
	}

	if licenseFile != "" {
		buf = bytes.NewBuffer(license)

		err = c.ssh.createFile(ctx, host, "/etc/teleport-license.pem", buf)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// setupNodeConfig will install the config on the given node.
func (c *Cluster) setupNodeConfig(ctx context.Context, host, proxyFQDN, inviteToken, caPin, nodeConfig string) error {
	buf := bytes.NewBuffer([]byte{})
	nodeConf, err := template.New("nodeConfig").Parse(nodeConfig)
	if err != nil {
		return trace.Wrap(err)
	}

	err = nodeConf.Execute(buf, configTemplate{
		ClusterName:      c.clusterName,
		ProxyFQDN:        proxyFQDN,
		LetsEncryptEmail: c.leEmail,
		LetsEncryptURI:   letsEncryptURI,
		InviteToken:      inviteToken,
		CAPin:            caPin,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	err = c.ssh.createFile(ctx, host, "/etc/teleport.yaml", buf)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// addTeleportToPath will add the Teleport binaries to the path.
func (c *Cluster) addTeleportToPath(ctx context.Context, host string) error {
	_, err := c.ssh.runCmd(ctx, host, `echo 'export PATH="/opt/teleport-ent:/opt/teleport:$PATH"' | sudo tee "/etc/profile.d/teleport-bin.sh"`)
	if err != nil {
		return trace.Wrap(err)
	}

	c.log.Infof("Teleport has been added to the path on host %s", host)

	return nil
}

// setupService will set up and start the Teleport systemd service.
func (c *Cluster) setupService(ctx context.Context, host string) error {
	if err := c.setupSystemd(ctx, host); err != nil {
		return trace.Wrap(err)
	}

	if err := c.enableAndStart(ctx, host); err != nil {
		return trace.Wrap(err)
	}

	c.log.Infof("Teleport has been enabled in systemd and started on %s", host)

	return nil
}

// setupSystemd will set up the Teleport systemd entry on the host.
func (c *Cluster) setupSystemd(ctx context.Context, host string) error {
	_, err := c.ssh.runCmd(ctx, host, `sudo -i teleport install systemd | sudo tee /etc/systemd/system/teleport.service`)
	return trace.Wrap(err)
}

// enableAndStart will enable the Teleport service on the host.
func (c *Cluster) enableAndStart(ctx context.Context, host string) error {
	_, err := c.ssh.runCmd(ctx, host, `sudo systemctl enable teleport && sudo systemctl start teleport`)
	return trace.Wrap(err)
}
