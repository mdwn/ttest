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
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/gravitational/trace"
	"github.com/mdwn/ttest/pkg/config"
	"github.com/sirupsen/logrus"
)

// BuildType is the type of Teleport binary to produce.
type BuildType string

const (
	// OSS will build the OSS version of Teleport.
	OSS BuildType = "OSS"
	// Enterprise will build the Enterprise version of Teleport.
	Enterprise BuildType = "enterprise"
	// FIPS will  build the FIPS Enterprise version of Teleport.
	FIPS BuildType = "fips"
)

// allBuildTypes is a list of all build types.
var allBuildTypes = []string{
	string(OSS),
	string(Enterprise),
	string(FIPS),
}

// Builder will build Teleport binaries.
type Builder struct {
	log       *logrus.Logger
	skipBuild bool
	srcDir    string
	buildType BuildType
}

// NewBuilder creates a new Teleport builder.
func NewBuilder(cfg *config.Config) (*Builder, error) {
	cfgBuildType := cfg.ClusterConfig.BuilderConfig.BuildType
	foundBuildType := true
	for _, buildType := range allBuildTypes {
		if buildType == cfgBuildType {
			foundBuildType = true
			break
		}
	}
	if !foundBuildType {
		return nil, trace.BadParameter("unable to find build type %s, expected one of %s", cfgBuildType, strings.Join(allBuildTypes, ","))
	}
	return &Builder{
		log:       cfg.Log,
		skipBuild: cfg.ClusterConfig.BuilderConfig.SkipBuild,
		srcDir:    cfg.ClusterConfig.BuilderConfig.SourceDir,
		buildType: BuildType(cfgBuildType),
	}, nil
}

// Build will build the Teleport binary. At the moment, this is hard coded
// to cross compile for amd64.
func (b *Builder) Build() ([]string, error) {
	if err := b.setupMac(); err != nil {
		return nil, trace.Wrap(err)
	}

	var buildTarget string
	var outputPath string
	buildEnv := append([]string{
		"CC=x86_64-unknown-linux-gnu-gcc",
		"OS=linux",
		"ARCH=amd64",
	}, os.Environ()...)
	switch b.buildType {
	case OSS:
		buildTarget = "full"
		outputPath = path.Join(b.srcDir, "build")
	case Enterprise:
		buildTarget = "full-ent"
		outputPath = path.Join(b.srcDir, "e", "build")
	case FIPS:
		buildTarget = "full-ent"
		outputPath = path.Join(b.srcDir, "e", "build")
		buildEnv = append(buildEnv, "FIPS=true")
	default:
		return nil, trace.BadParameter("unsupported build type %s", b.buildType)
	}

	if b.skipBuild {
		b.log.Infof("Build has been skipped.")
	} else {
		// Build Teleport.
		cmd := exec.Command("make", buildTarget)
		cmd.Dir = b.srcDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = buildEnv

		if err := cmd.Run(); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	entries, err := os.ReadDir(outputPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var fileNames []string
	for _, entry := range entries {
		fileNames = append(fileNames, path.Join(outputPath, entry.Name()))
	}
	return fileNames, nil
}

// setupMac will install cross compilation toolchains on Mac, assuming the user has brew.
func (b *Builder) setupMac() error {
	cmd := exec.Command("uname", "-s")
	kernelNameBytes, err := cmd.Output()
	if err != nil {
		return trace.Wrap(err)
	}
	kernelName := strings.TrimSpace(string(kernelNameBytes))

	if string(kernelName) != "Darwin" {
		b.log.Infof("kernelName: %s", string(kernelName))
		b.log.Infof("Builder is not a Mac, so skipping this setup.")
		return nil
	}

	// Tap the Mac OS cross toolchains
	b.log.Infof("Tapping the Mac OS cross toolchains.")
	cmd = exec.Command("brew", "tap", "messense/macos-cross-toolchains")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return trace.Wrap(err)
	}

	// Install the x86_64 linux arch
	b.log.Infof("Installing the Mac OS cross toolchains.")
	cmd = exec.Command("brew", "install", "x86_64-unknown-linux-gnu")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return trace.Wrap(cmd.Run())
}
