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
	"testing"

	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/stretchr/testify/require"
)

func TestOutputUnmarshal(t *testing.T) {
	output := map[string]tfexec.OutputMeta{
		"test1": {
			Value: []byte("1"),
		},
		"test2": {
			Value: []byte("\"12345\""),
		},
	}

	v := struct {
		Test1 int    `tf_output:"test1"`
		Test2 string `tf_output:"test2"`
	}{}

	require.NoError(t, unmarshalOutput(output, &v))

	require.Equal(t, 1, v.Test1)
	require.Equal(t, "12345", v.Test2)

	require.NoError(t, unmarshalOutput(output, nil))
	require.NoError(t, unmarshalOutput(output, []byte(nil)))
}
