/*
Copyright 2026.

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

package rules

import (
	"reflect"
	"strings"
	"testing"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

// SecurityPolicy.spec.rules must offer exactly the namespace-configurable rules of the
// catalog, under the same keys. RBAC rules are configured operator-wide only.
func TestPolicyRuleKeysMatchCatalog(t *testing.T) {
	fields := map[string]bool{}
	for field := range reflect.TypeFor[securityv1alpha1.RuleOverrides]().Fields() {
		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		fields[key] = true
		m, ok := ByKey(key)
		if !ok {
			t.Errorf("spec.rules.%s has no rule in the catalog", key)
			continue
		}
		if m.Scope == ScopeRBAC {
			t.Errorf("spec.rules.%s: RBAC rules must not be namespace-configurable", key)
		}
	}
	for _, m := range Catalog {
		if m.Scope != ScopeRBAC && !fields[m.Key] {
			t.Errorf("%s (%s) is missing from SecurityPolicy spec.rules", m.ID, m.Key)
		}
	}
}
