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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// tctlClient is a client that runs tctl commands on the host.
type tctlClient struct {
	log  *logrus.Logger
	ssh  *sshClient
	host string
}

// newTCTLClient creates a new tctl client.
func newTCTLClient(log *logrus.Logger, ssh *sshClient, host string) *tctlClient {
	return &tctlClient{
		log:  log,
		ssh:  ssh,
		host: host,
	}
}

// waitForStart will wait for Teleport to start until the ttl.
func (t *tctlClient) waitForStart(ctx context.Context, ttl time.Duration) error {
	timer := time.NewTimer(ttl)
	for {
		select {
		case <-ctx.Done():
			return trace.BadParameter("context timeout waiting for Teleport start")
		case <-timer.C:
			return trace.BadParameter("timeout waiting for Teleport start")
		case <-time.After(1 * time.Second):
		}

		if _, err := t.ssh.runCmd(ctx, t.host, "sudo /opt/teleport/tctl status"); err == nil {
			return nil
		}
	}
}

func (t *tctlClient) runCommand(ctx context.Context, command []string) error {
	fullCommand := append([]string{"sudo", "/opt/teleport/tctl"}, command...)
	return t.ssh.runUserCommand(ctx, t.host, fullCommand)
}

// trustedClusterToken creates a trusted cluster token.
func (t *tctlClient) trustedClusterToken(ctx context.Context) (string, error) {
	output, err := t.ssh.runCmd(ctx, t.host,
		`sudo /opt/teleport/tctl tokens add --type=trusted_cluster --ttl=5m | grep "invite token:" | grep -Eo "[0-9a-z]{32}"`)
	return strings.TrimSpace(output), trace.Wrap(err)
}

// inviteToken creates an invite token.
func (t *tctlClient) inviteToken(ctx context.Context, roles []string) (string, error) {
	output, err := t.ssh.runCmd(ctx, t.host,
		fmt.Sprintf(`sudo /opt/teleport/tctl nodes add --ttl=5m --roles=%q | grep "invite token:" | grep -Eo "[0-9a-z]{32}"`,
			strings.Join(roles, ",")))
	return strings.TrimSpace(output), trace.Wrap(err)
}

// caPin will return the CA pin for the Teleport server.
func (t *tctlClient) caPin(ctx context.Context) (string, error) {
	output, err := t.ssh.runCmd(ctx, t.host, "sudo /opt/teleport/tctl status | awk '/CA pin/{print $3}'")
	return strings.TrimSpace(output), trace.Wrap(err)
}
