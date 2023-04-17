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
	"embed"
	"os"
	"path"
	"strings"

	"github.com/gravitational/trace"
)

const (
	assetsSubDir = "assets"
	modules      = "modules"
)

//go:embed assets
var assets embed.FS

// copyAssetsToDir will copy the Terraform assets from the asset path to the target directory,
// cleaning the .tf files from the target directory first.
func copyAssetsToDir(assetPath string, targetDir string) error {
	// Before copying the assets, clear the existing .tf files from the directory, preserving the state.
	if err := clearTFFromDir(targetDir); err != nil {
		return trace.Wrap(err)
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return trace.Wrap(err)
	}

	entries, err := assets.ReadDir(path.Join(assetsSubDir, assetPath))
	if err != nil {
		return trace.Wrap(err)
	}

	for _, entry := range entries {
		assetFile := path.Join(assetPath, entry.Name())
		if entry.IsDir() {
			continue
		}

		input, err := assets.ReadFile(path.Join(assetsSubDir, assetFile))
		if err != nil {
			return trace.Wrap(err)
		}

		if err := os.WriteFile(path.Join(targetDir, entry.Name()), input, 0o644); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// clearTFFromDir will clear out .tf files from the given directory.
func clearTFFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, entry := range entries {
		targetPath := path.Join(dir, entry.Name())
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".tf") {
			if err := os.Remove(targetPath); err != nil {
				return trace.Wrap(err)
			}
		}
	}

	return nil
}
