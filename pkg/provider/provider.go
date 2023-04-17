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

package provider

import (
	"context"

	"github.com/gravitational/trace"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/mdwn/ttest/pkg/provider/aws"
)

// Provider is an interface that will create and manage Teleport clusters.
type Provider interface {
	// Create will create the necessary infrastructure for a Teleport cluster.
	Create(context.Context) error

	// Destroy will destroy all infrastructure for a Teleport cluster.
	Destroy(context.Context) error

	// ServerHost will return the host of the server. It is expected to be connectable with SSH via port 22.
	ServerHost(context.Context) (string, error)

	// Nodes will return the node hosts. It is expected to be connectable with SSH via port 22. The order of the
	// nodes is expected to be stable between runs.
	Nodes(context.Context) ([]string, error)

	// ProxyFQDN will return the FQDN of the proxy.
	ProxyFQDN(context.Context) (string, error)
}

// Get will return a provider given the configuration.
func Get(ctx context.Context, cfg *config.Config) (Provider, error) {
	if cfg.ClusterConfig.AWSConfig != nil {
		return aws.NewProvider(ctx, cfg)
	}

	return nil, trace.BadParameter("no provider configuration found")
}
