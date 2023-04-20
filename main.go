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

package main

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/trace"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/mdwn/ttest/pkg/teleport"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	ttestDefaultSubdir = "src/ttest-clusters"
	ttestClusterDirEnv = "TTEST_CLUSTERS_DIR"
)

var (
	log = logrus.New()
)

func main() {
	ctx := context.Background()

	ttestDir := os.Getenv(ttestClusterDirEnv)
	if ttestDir == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			log.Errorf("error finding home directory: %v", err)
		} else {
			ttestDir = path.Join(homedir, ttestDefaultSubdir)
		}
	}

	var configDir, clusterName, nodeName string
	var command []string

	rootCmd := kingpin.New("teleport-deploy", "A utility to deploy and establish a Teleport cluster.")
	rootCmd.Flag("configs", "The directory full of cluster configurations").Short('c').Default(ttestDir).StringVar(&configDir)

	createCmd := rootCmd.Command("create", "Creates or updates a Teleport cluster.")
	createCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)

	deployCmd := rootCmd.Command("deploy", "Deploys Teleport binaries to the cluster.")
	deployCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)

	destroyCmd := rootCmd.Command("destroy", "Destroys a Teleport cluster.")
	destroyCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)

	nodesCmd := rootCmd.Command("nodes", "Interacts with the nodes on a Teleport cluster.")

	nodesLsCmd := nodesCmd.Command("ls", "Lists the nodes for the cluster.")
	nodesLsCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)

	nodesSshCmd := nodesCmd.Command("ssh", "Creates an interactive SSH session to the node.")
	nodesSshCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)
	nodesSshCmd.Arg("node-name", "The name of the node.").Required().StringVar(&nodeName)
	nodesSshCmd.Arg("command", "An optional command for the node").StringsVar(&command)

	tctlCmd := rootCmd.Command("tctl", "Runs an arbitrary tctl command against the cluster.")
	tctlCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)
	tctlCmd.Arg("command", "An optional command for the node").StringsVar(&command)

	storeCmd := rootCmd.Command("store", "Interacts with the ttest store.")

	storeDirCmd := storeCmd.Command("dir", "Displays the store directory for the given cluster")
	storeDirCmd.Arg("cluster-name", "The name of the cluster.").Required().StringVar(&clusterName)

	parseResult, err := rootCmd.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("error parsing command line: %v", err)
	}

	configFileDir := path.Join(configDir, clusterName+".yaml")
	cfg, err := config.New(log, clusterName, configFileDir)
	if err != nil {
		log.Fatalf("error during configuration: %v", err)
	}

	provisioner, err := teleport.NewProvisioner(ctx, cfg)
	if err != nil {
		log.Fatalf("error during provisioner creation: %v", err)
	}

	switch parseResult {
	case createCmd.FullCommand():
		if err := create(ctx, provisioner); err != nil {
			log.Fatalf("error creating cluster: %v", err)
		}
	case deployCmd.FullCommand():
		if err := deploy(ctx, provisioner); err != nil {
			log.Fatalf("error deploying to cluster: %v", err)
		}
	case destroyCmd.FullCommand():
		if err := destroy(ctx, provisioner); err != nil {
			log.Fatalf("error destroying cluster: %v", err)
		}
	case nodesLsCmd.FullCommand():
		if err := nodesLs(ctx, provisioner); err != nil {
			log.Fatalf("error listing nodes: %v", err)
		}
	case nodesSshCmd.FullCommand():
		if err := nodesSsh(ctx, provisioner, nodeName, command...); err != nil {
			if exitError, ok := err.(*ssh.ExitError); ok {
				os.Exit(exitError.ExitStatus())
			}
			log.Fatalf("error creating an SSH connection to node %s: %v", nodeName, err)
		}
	case tctlCmd.FullCommand():
		if err := tctl(ctx, provisioner, command...); err != nil {
			if exitError, ok := err.(*ssh.ExitError); ok {
				os.Exit(exitError.ExitStatus())
			}
			log.Fatalf("error running tctl command%v", err)
		}
	case tctlCmd.FullCommand():
	case storeDirCmd.FullCommand():
		storeDir(cfg)
	}
}

func create(ctx context.Context, provisioner *teleport.Provisioner) error {
	return trace.Wrap(provisioner.Create(ctx))
}

func deploy(ctx context.Context, provisioner *teleport.Provisioner) error {
	return trace.Wrap(provisioner.Deploy(ctx))
}

func destroy(ctx context.Context, provisioner *teleport.Provisioner) error {
	return trace.Wrap(provisioner.Destroy(ctx))
}

func nodesLs(ctx context.Context, provisioner *teleport.Provisioner) error {
	nodes, err := provisioner.Nodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	fmt.Printf("%-15s%s\n", "Node Name", "Host")
	fmt.Println("------------------------------")
	for name, node := range nodes {
		fmt.Printf("%-15s%s\n", name, node.Host)
	}

	return nil
}

func nodesSsh(ctx context.Context, provisioner *teleport.Provisioner, nodeName string, command ...string) error {
	return provisioner.SSH(ctx, nodeName, command...)
}

func tctl(ctx context.Context, provisioner *teleport.Provisioner, command ...string) error {
	return provisioner.TCTL(ctx, command...)
}

func storeDir(cfg *config.Config) {
	fmt.Println(cfg.ClusterConfig.StoreDir)
}
