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

package aws

import (
	"context"
	"fmt"

	"github.com/gravitational/trace"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/mdwn/ttest/pkg/terraform"
	"github.com/sirupsen/logrus"
)

const (
	// awsKey is a module that will create a new AWS key pair.
	awsKey terraform.Module = "modules/aws/key"
	// awsCluster is a module that will create a new AWS Teleport cluster.
	awsCluster terraform.Module = "modules/aws/cluster"
	// awsRegion is a module that will return the currently configured region.
	awsRegion terraform.Module = "modules/aws/region"

	awsKeyState        = "aws/key"
	clusterStateFormat = "aws/cluster/%s"
	regionState        = "aws/region"
)

// Provider is an AWS provider that can create a Teleport cluster in AWS.
type Provider struct {
	log           *logrus.Logger
	publicKey     string
	clusterName   string
	nodeCount     int
	route53Domain string
	vpcID         string
	amiID         string
	tfClient      *terraform.Client
}

// NewProvider will create a new AWS Teleport cluster provider.
func NewProvider(ctx context.Context, cfg *config.Config) (*Provider, error) {
	tfClient, err := terraform.New(ctx, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	amiID := cfg.ClusterConfig.AWSConfig.AMI
	if amiID == "" {
		var output regionOutput
		err := tfClient.Apply(ctx, awsRegion, regionState, &output)
		if err != nil {
			return nil, trace.Wrap(err, "AMI was not supplied and unable to find currently configured region")
		}

		var ok bool
		amiID, ok = amiDefaults[output.Region]
		if !ok {
			return nil, trace.NotFound("unable to find default AMI for region %s", output.Region)
		}

		cfg.Log.Infof("Using default AMI %s for region %s", amiID, output.Region)
	}

	return &Provider{
		log:           cfg.Log,
		publicKey:     string(cfg.ClusterConfig.GetPublicKey()),
		clusterName:   cfg.ClusterName,
		nodeCount:     len(cfg.ClusterConfig.NodeConfigs),
		route53Domain: cfg.ClusterConfig.AWSConfig.Route53Domain,
		vpcID:         cfg.ClusterConfig.AWSConfig.VPCID,
		amiID:         amiID,
		tfClient:      tfClient,
	}, nil
}

// Create will create the necessary infrastructure for a Teleport cluster.
func (p *Provider) Create(ctx context.Context) error {
	var output keyModuleOutput
	err := p.tfClient.Apply(ctx, awsKey, awsKeyState, &output, "public_key", string(p.publicKey))
	if err != nil {
		return trace.Wrap(err)
	}

	err = p.tfClient.Apply(ctx, awsCluster, fmt.Sprintf(clusterStateFormat, p.clusterName), nil,
		"route53_domain", p.route53Domain,
		"vpc_id", p.vpcID,
		"key_name", output.KeyName,
		"cluster_name", p.clusterName,
		"node_count", p.nodeCount)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// Destroy will destroy all AWS resources. It will leave the key for future use.
func (p *Provider) Destroy(ctx context.Context) error {
	return trace.Wrap(p.tfClient.Destroy(ctx, awsCluster, fmt.Sprintf(clusterStateFormat, p.clusterName)))
}

// ServerHost will return the host of the server.
func (p *Provider) ServerHost(ctx context.Context) (string, error) {
	var output clusterModuleOutput
	err := p.tfClient.Output(ctx, awsCluster, fmt.Sprintf(clusterStateFormat, p.clusterName), &output)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return output.ServerIP, nil
}

// Nodes will return the node hosts.
func (p *Provider) Nodes(ctx context.Context) ([]string, error) {
	var output clusterModuleOutput
	err := p.tfClient.Output(ctx, awsCluster, fmt.Sprintf(clusterStateFormat, p.clusterName), &output)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return output.NodeIPs, nil
}

// ProxyFQDN will return the FQDN of the proxy.
func (p *Provider) ProxyFQDN(ctx context.Context) (string, error) {
	var output clusterModuleOutput
	err := p.tfClient.Output(ctx, awsCluster, fmt.Sprintf(clusterStateFormat, p.clusterName), &output)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return output.ProxyFQDN, nil
}

// output of the key module.
type keyModuleOutput struct {
	KeyName string `tf_output:"key_name"`
}

// output of the cluster module.
type clusterModuleOutput struct {
	ServerIP  string   `tf_output:"server_ip"`
	NodeIPs   []string `tf_output:"node_ips"`
	ProxyFQDN string   `tf_output:"proxy_fqdn"`
}

type regionOutput struct {
	Region string `tf_output:"region"`
}
