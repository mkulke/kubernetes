/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package v0

import (
	"k8s.io/kubernetes/pkg/auth/authorizer/abac/api"
	"k8s.io/kubernetes/pkg/conversion"
)

func init() {
	api.Scheme.AddConversionFuncs(
		func(in *Policy, out *api.Policy, s conversion.Scope) error {
			// Begin by copying all fields
			err := s.DefaultConvert(in, out, conversion.IgnoreMissingFields)
			if err != nil {
				return err
			}

			// In v0, unspecified user and group matches all subjects
			if len(in.User) == 0 && len(in.Group) == 0 {
				out.User = "*"
			}

			// In v0, leaving namespace empty matches all namespaces
			if len(in.Namespace) == 0 {
				out.Namespace = "*"
			}
			// In v0, leaving resource empty matches all resources
			if len(in.Resource) == 0 {
				out.Resource = "*"
			}
			// Any rule in v0 should match all API groups
			out.ResourceGroup = "*"

			// In v0, leaving namespace and resource blank allows non-resource paths
			if len(in.Namespace) == 0 && len(in.Resource) == 0 {
				out.NonResourcePath = "*"
			}

			return nil
		},
	)
}
