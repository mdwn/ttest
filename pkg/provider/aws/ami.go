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

// Ubuntu 22.04, collected from https://cloud-images.ubuntu.com/locator/ec2/
var amiDefaults = map[string]string{
	"af-south-1":     "ami-0db5d423435a72e9c",
	"ap-east-1":      "ami-01ae7941db3ae786a",
	"ap-northeast-1": "ami-0cba3eef5c6b97a50",
	"ap-northeast-2": "ami-0785accd4f9bbbbe3",
	"ap-northeast-3": "ami-0c354d4325a8fbc6d",
	"ap-south-1":     "ami-016c2e7c8b793cd9c",
	"ap-south-2":     "ami-04951bc85a38bcb50",
	"ap-southeast-1": "ami-0867f2f0e7e53730c",
	"ap-southeast-2": "ami-04db1dd83bf8236f6",
	"ap-southeast-3": "ami-08990800c8dc50975",
	"ap-southeast-4": "ami-0a721918c74ddbf29",
	"ca-central-1":   "ami-0bfd6fd269ca8f19a",
	"eu-central-1":   "ami-0c3220f58e051423c",
	"eu-central-2":   "ami-0d23517281b618c1e",
	"eu-north-1":     "ami-0430d9174f123719e",
	"eu-south-1":     "ami-0218b4d066ef21ec3",
	"eu-south-2":     "ami-00c3387c08762df3f",
	"eu-west-1":      "ami-09b0d7d31ba756f46",
	"eu-west-2":      "ami-0eb27879c20e8bf16",
	"eu-west-3":      "ami-0df664fa5753e1e2d",
	"me-central-1":   "ami-0dc3d9f37166101b3",
	"me-south-1":     "ami-0f7b96f74d84b02e8",
	"sa-east-1":      "ami-091477d92baa0228e",
	"us-east-1":      "ami-0b5df848226550db1",
	"us-east-2":      "ami-0d29ed4b66716fd4a",
	"us-west-1":      "ami-06730e546047b68df",
	"us-west-2":      "ami-0e4a0595b254f1a4f",
}
