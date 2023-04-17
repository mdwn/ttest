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

package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/gravitational/trace"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/sirupsen/logrus"
)

type Module string

const (
	// AWSKey is a module that will create a new AWS key pair.
	AWSKey Module = "modules/aws/key"
	// AWSCluster is a module that will create a new AWS Teleport cluster.
	AWSCluster Module = "modules/aws/cluster"

	// stateSubdir is the directory where all state will be stored. Will be in a subdirectory under the
	// configured store directory.
	stateSubdir = "state"

	// tfVarsFile
	tfVarsFile = "terraform.tfvars.json"
)

// Client is a Terraform CLI wrapper.
type Client struct {
	log      *logrus.Logger
	stateDir string
	execPath string
}

// New creates a Terraform CLI wrapper.
func New(ctx context.Context, cfg *config.Config) (*Client, error) {
	log := cfg.Log
	execPath := cfg.ClusterConfig.TerraformConfig.ExecPath
	stateDir := path.Join(cfg.ClusterConfig.StoreDir, stateSubdir)
	version := cfg.ClusterConfig.TerraformConfig.GetVersion()
	// Make sure the store directory exists
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, trace.Wrap(err)
	}

	// If an exec path has already been supplied, use this instead
	if execPath != "" {
		return &Client{
			log:      log,
			stateDir: stateDir,
			execPath: execPath,
		}, nil
	}

	// If not, we'll either install terraform into the data store or use the existing installation in the store.
	installer := &releases.ExactVersion{
		Product:    product.Terraform,
		Version:    version,
		InstallDir: stateDir,
	}

	// Check if Terraform is currently installed in the store directory and check its version.
	execPath = path.Join(stateDir, installer.Product.BinaryName())
	tf, err := tfexec.NewTerraform(stateDir, execPath)
	installationIsValid := false
	if err != nil {
		log.Errorf("Terraform cannot be initialized, will install into %s.", stateDir)
	} else {
		installedVersion, _, err := tf.Version(ctx, false)
		if err != nil {
			log.Errorf("error getting version, will install into %s.", stateDir)
		}

		if installedVersion.Equal(version) {
			installationIsValid = true
			log.Debugf("Terraform is already installed in %s.", stateDir)
		} else {
			log.Errorf("Version %s does not match intended install version %s, will update.", installedVersion, installer.Version)
		}
	}

	// If the installation isn't valid, install Terraform into the store.
	if !installationIsValid {
		var err error

		log.Infof("Installing Terraform %s...", installer.Version)
		execPath, err = installer.Install(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		log.Infof("Terraform installed successfully")
	}

	return &Client{
		log:      log,
		execPath: execPath,
		stateDir: stateDir,
	}, nil
}

// Apply will apply the given module, creating the infrastructure if needed. The output will be unmarshaled into v.
func (c *Client) Apply(ctx context.Context, module Module, stateSuffix string, v any, vars ...interface{}) error {
	state := path.Join(c.stateDir, stateSuffix)

	if err := os.MkdirAll(state, 0o755); err != nil {
		return trace.Wrap(err)
	}

	// Copy the assets into the state directory.
	if err := copyAssetsToDir(string(module), state); err != nil {
		return trace.Wrap(err)
	}

	tf, err := c.makeTfExec(ctx, state)
	if err != nil {
		return trace.Wrap(err)
	}

	err = c.createVarFile(state, vars...)
	if err != nil {
		return trace.Wrap(err)
	}

	// Apply Terraform.
	c.log.Infof("Applying %s in directory %s", module, state)
	if err := tf.Apply(ctx); err != nil {
		return trace.Wrap(err)
	}

	// Return the output.
	return trace.Wrap(c.outputWithClient(ctx, v, tf))
}

// Output returns the output from a terraform module by unmarshaling it into v. Apply must have been run first.
func (c *Client) Output(ctx context.Context, targetModule Module, stateSuffix string, v any) error {
	state := path.Join(c.stateDir, stateSuffix)
	tf, err := c.makeTfExec(ctx, state)
	if err != nil {
		return trace.Wrap(err)
	}

	// Return the output.
	return trace.Wrap(c.outputWithClient(ctx, v, tf))
}

// outputWithClient will unmarshal the output into v given the tf client.
func (c *Client) outputWithClient(ctx context.Context, v any, tf *tfexec.Terraform) error {
	// Get the output from the module.
	tfOutput, err := tf.Output(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Unmarshal all of the raw JSON values from the output.
	if err := unmarshalOutput(tfOutput, v); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// Destroy the infrastructure behind the given module.
func (c *Client) Destroy(ctx context.Context, targetModule Module, stateSuffix string, vars ...interface{}) error {
	state := path.Join(c.stateDir, stateSuffix)
	tf, err := c.makeTfExec(ctx, state)
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(tf.Destroy(ctx))
}

// makeTfExec makes a terraform exec object.
func (c *Client) makeTfExec(ctx context.Context, state string) (*tfexec.Terraform, error) {
	tf, err := tfexec.NewTerraform(state, c.execPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = tf.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return tf, nil
}

// createVarFile creates a var file and puts it into the state directory, which will be automatically loaded by Terraform.
func (c *Client) createVarFile(state string, vars ...interface{}) error {
	numVars := len(vars)
	if numVars == 0 {
		return nil
	}

	if numVars%2 != 0 {
		return trace.BadParameter("vars must be in name/value pairs")
	}

	varMap := map[string]interface{}{}
	for i := 0; i < numVars; i = i + 2 {
		varMap[fmt.Sprintf("%s", vars[i])] = vars[i+1]
	}

	file, err := os.OpenFile(path.Join(state, tfVarsFile), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		file.Close()
	}()

	encoder := json.NewEncoder(file)
	return trace.Wrap(encoder.Encode(varMap))
}
