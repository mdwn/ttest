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

package config

import (
	_ "embed"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/gravitational/trace"
	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// The default server configuration template.
//
//go:embed assets/defaultserverconf.yaml.tpl
var defaultServerConf string

const (
	// srcInGopath is the location we expect Teleport to be on a developer system.
	srcInGopath             = "src/github.com/gravitational/teleport"
	defaultTfStoreDir       = "teleport-deploy-store"
	defaultTerraformVersion = "1.3.9"
)

// Config is a config for the entire deployment application.
type Config struct {
	// Log is the logger for the entire application.
	Log *logrus.Logger

	// ClusterName is the name of the cluster to operate on.
	ClusterName string

	// ClusterConfig is the cluster configuration.
	ClusterConfig *ClusterConfig
}

// New will create a new config file by loading most of the values from configFile.
func New(log *logrus.Logger, clusterName, configFile string) (*Config, error) {
	cfg := &Config{
		Log:           log,
		ClusterName:   clusterName,
		ClusterConfig: &ClusterConfig{},
	}

	log.Debugf("Reading %s", configFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := yaml.Unmarshal(data, cfg.ClusterConfig); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return cfg, nil
}

func (c *Config) checkAndSetDefaults() error {
	if c.Log == nil {
		c.Log = logrus.New()
	}
	if c.ClusterName == "" {
		return trace.BadParameter("cluster name is missing")
	}
	if c.ClusterConfig == nil {
		return trace.BadParameter("cluster config is missing")
	}
	if err := c.ClusterConfig.checkAndSetDefaults(c.Log); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// ClusterrConfig is the configuration for the cluster.
type ClusterConfig struct {
	// StoreDir is a store for the local program state.
	StoreDir string `yaml:"store_dir"`

	// ServerConfig is the configuration for the Teleport server.
	ServerConfig string `yaml:"server_config"`

	// PrivateKeyFile is the private key file used to connect to remote instances.
	PrivateKeyFile string `yaml:"private_key_file,omitempty"`

	// PrivateKeyPassphrase is the passphrase to use for the private key.
	PrivateKeyPassphrase string `yaml:"private_key_passphrase,omitempty"`

	// PublicKeyFile is the public key file used to connect to remote instances.
	PublicKeyFile string `yaml:"public_key_file"`

	// LetsEncryptEmail is the e-mail address to use with let's encrypt.
	LetsEncryptEmail string `yaml:"lets_encrypt_email"`

	// License is the Teleport license.
	LicenseFile string `yaml:"license_file"`

	// TerraformConfig is the configuration for the Terraform client.
	TerraformConfig *TerraformConfig `yaml:"terraform"`

	// AWSConfig is the configuration for AWS provider (if used).
	AWSConfig *AWSConfig `yaml:"aws,omitempty"`

	// BuilderConfig is the configuration for the Teleport builder (if used).
	BuilderConfig *BuilderConfig `yaml:"builder"`

	// ProvisionerConfig is the configuration for the Teleport provisioner (if used).
	ProvisionerConfig *ProvisionerConfig `yaml:"provisioner"`

	// NodeConfigs is Teleport configuration files for each node.
	NodeConfigs map[string]NodeRolesAndConfig `yaml:"nodes"`

	license    []byte
	privateKey []byte
	publicKey  []byte
}

// NodeRoelsAndConfig contains the node rules and config.
type NodeRolesAndConfig struct {
	Roles  []string `yaml:"roles"`
	Config string   `yaml:"config"`
}

func (c *ClusterConfig) checkAndSetDefaults(log *logrus.Logger) error {
	// Set some defaults.
	if c.TerraformConfig == nil {
		c.TerraformConfig = &TerraformConfig{}
	}
	if c.BuilderConfig == nil {
		c.BuilderConfig = &BuilderConfig{}
	}
	if c.ProvisionerConfig == nil {
		c.ProvisionerConfig = &ProvisionerConfig{}
	}
	if c.NodeConfigs == nil {
		c.NodeConfigs = map[string]NodeRolesAndConfig{}
	}

	if c.StoreDir == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return trace.WrapWithMessage(err, "unable to get config dir")
		}

		c.StoreDir = path.Join(configDir, defaultTfStoreDir)
	}

	if c.ServerConfig == "" {
		c.ServerConfig = defaultServerConf
	}

	var err error
	if c.PrivateKeyFile != "" {
		c.privateKey, err = os.ReadFile(c.PrivateKeyFile)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	if c.PublicKeyFile != "" {
		c.publicKey, err = os.ReadFile(c.PublicKeyFile)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	if c.LetsEncryptEmail == "" {
		return trace.BadParameter("let's encrypt e-mail is missing")
	}
	if c.LicenseFile != "" {
		var err error
		c.license, err = os.ReadFile(c.LicenseFile)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	if err := c.TerraformConfig.checkAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if c.AWSConfig != nil {
		if err := c.AWSConfig.checkAndSetDefaults(); err != nil {
			return trace.Wrap(err)
		}
	}
	if err := c.BuilderConfig.checkAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if err := c.ProvisionerConfig.checkAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// GetPublicKey gets the contents of the public key file.
func (c *ClusterConfig) GetPublicKey() []byte {
	return c.publicKey
}

// GetPrivateKey gets the contents of the private key file.
func (c *ClusterConfig) GetPrivateKey() []byte {
	return c.privateKey
}

// GetLicense gets the contents of the license key file.
func (c *ClusterConfig) GetLicense() []byte {
	return c.license
}

// AWSConfig is configuration for the AWS provider.
type AWSConfig struct {
	Enabled bool `yaml:"enabled"`

	// Route53Domain is the route 53 domain to set up the cluster in.
	Route53Domain string `yaml:"route53_domain"`

	// VPCID is the VPC ID to set up AWS instances in.
	VPCID string `yaml:"vpc_id"`

	// The AMI to use.
	AMI string `yaml:"ami"`
}

func (c *AWSConfig) checkAndSetDefaults() error {
	if !c.Enabled {
		return nil
	}

	if c.Route53Domain == "" {
		return trace.BadParameter("route53 domain is missing")
	}

	if c.VPCID == "" {
		return trace.BadParameter("vpc ID is missing")
	}

	return nil
}

// TerraformConfig is configuration for the Terraform exec wrapper.
type TerraformConfig struct {
	// ExecPath is an optional path to Terraform if a user wants to use a locally installed Terraform.
	ExecPath string `yaml:"exec_path"`

	// Version is the version of Terraform to install.
	Version string `yaml:"version"`

	parsedVersion *version.Version
}

func (c *TerraformConfig) checkAndSetDefaults() error {
	if c.Version == "" {
		c.Version = defaultTerraformVersion
	}
	var err error
	c.parsedVersion, err = version.NewVersion(c.Version)
	if err != nil {
		return trace.BadParameter("version is invalid")
	}

	return nil
}

// GetVersion returns the parsed version of the version string.
func (c *TerraformConfig) GetVersion() *version.Version {
	return c.parsedVersion
}

// BuilderConfig is configuration for the Teleport builder.
type BuilderConfig struct {
	// SkipBuild indicates whether we should skip building Teleport.
	SkipBuild bool `yaml:"skip_build"`

	// SourceDir is the source directory for Teleport.
	SourceDir string `yaml:"source_dir"`

	// BuildType is the what type of Teleport binary to generate.
	BuildType string `yaml:"build_type"`
}

func (c *BuilderConfig) checkAndSetDefaults() error {
	// If the source directory is empty, we'll attempt to detect it.
	if c.SourceDir == "" {
		var err error
		c.SourceDir, err = c.detectSourceDirectory()
		if err != nil {
			return trace.Wrap(err)
		}
	}
	if c.BuildType == "" {
		return trace.BadParameter("build type is missing")
	}

	return nil
}

// detectSourceDirectory attempts to find the Teleport source directory by finding
// the GOPATH and appending the expected path for it.
func (c *BuilderConfig) detectSourceDirectory() (string, error) {
	// Find the GOPATH.
	cmd := exec.Command("go", "env", "GOPATH")
	output, err := cmd.Output()
	if err != nil {
		return "", trace.Wrap(err)
	}

	srcDir := path.Join(strings.TrimSpace(string(output)), srcInGopath)
	if info, err := os.Stat(srcDir); err == nil {
		if info.IsDir() {
			return srcDir, nil
		}

		return "", trace.BadParameter("%s is not a directory", srcDir)
	}

	return "", trace.NotFound("unable to find Teleport source directory")
}

// ProvisionerConfig is the configuration for the provisioner.
type ProvisionerConfig struct {
	// User is the user to use to SSH into a node.
	User string `yaml:"user"`

	// TeleportTarURL is the URL of the Teleport tarball to use. If this is used, the builder
	// will not be run and this URL will be downloaded instead.
	TeleportTarURL string `yaml:"teleport_tar_url"`
}

func (c *ProvisionerConfig) checkAndSetDefaults() error {
	if c.User == "" {
		c.User = "ubuntu"
	}

	return nil
}
