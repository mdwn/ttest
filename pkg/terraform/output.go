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
	"encoding/json"
	"reflect"

	"github.com/gravitational/trace"
	"github.com/hashicorp/terraform-exec/tfexec"
)

// unmarshalOutput will unmarshal the output given into a struct with `tf_output` tags that have the value of the
// expected field names of the tf_output.
func unmarshalOutput(o map[string]tfexec.OutputMeta, v any) error {
	p := reflect.ValueOf(v)

	// Don't unmarshal nil.
	if p.Kind() == reflect.Invalid || p.IsNil() {
		return nil
	}

	// Make sure this is a pointer to a struct.
	if p.Kind() != reflect.Pointer {
		return trace.BadParameter("input is supposed to be a pointer to a struct, (not a pointer) got %T", v)
	}

	s := p.Elem()
	if s.Kind() != reflect.Struct {
		return trace.BadParameter("input is supposed to be a pointer to a struct, (not a struct) got %T", v)
	}

	// Look through each field.
	for i := 0; i < s.NumField(); i++ {
		field := s.Type().Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// If there is no output tag, skip.
		outputTagValue := field.Tag.Get("tf_output")
		if outputTagValue == "" {
			continue
		}

		tfOutput, ok := o[outputTagValue]
		if !ok {
			continue
		}

		// Each value in the OutputMeta structure is raw JSON, so we should just attempt to unmarshal
		// directly into the struct field.
		val := interface{}(s.Field(i).Addr().Interface())
		if err := json.Unmarshal(tfOutput.Value, val); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}
