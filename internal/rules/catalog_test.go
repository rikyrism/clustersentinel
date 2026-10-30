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
	"regexp"
	"testing"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

func TestCatalogIsConsistent(t *testing.T) {
	idPattern := regexp.MustCompile(`^CS-[A-Z]+-[0-9]{3}$`)
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, m := range Catalog {
		if !idPattern.MatchString(m.ID) {
			t.Errorf("%s: ID does not match the CRD pattern", m.ID)
		}
		if ids[m.ID] || keys[m.Key] {
			t.Errorf("%s/%s: duplicate ID or key", m.ID, m.Key)
		}
		ids[m.ID], keys[m.Key] = true, true
		if !m.DefaultSeverity.IsValid() {
			t.Errorf("%s: invalid default severity %q", m.ID, m.DefaultSeverity)
		}
		if m.Version < 1 {
			t.Errorf("%s: version must be >= 1", m.ID)
		}
		if m.EnabledIn(securityv1alpha1.ProfileCustom) {
			t.Errorf("%s: the custom profile must not enable rules implicitly", m.ID)
		}
		if !m.EnabledIn(securityv1alpha1.ProfileStrict) {
			t.Errorf("%s: strict must enable every rule", m.ID)
		}
		if m.EnabledIn(securityv1alpha1.ProfileBasic) && !m.EnabledIn(securityv1alpha1.ProfileRecommended) {
			t.Errorf("%s: profiles must be nested (basic ⊆ recommended)", m.ID)
		}
	}
	if len(Catalog) != 18 {
		t.Errorf("expected 18 rules, got %d", len(Catalog))
	}
}

func TestLookups(t *testing.T) {
	m, ok := ByKey("privilegedContainer")
	if !ok || m.ID != "CS-CONTAINER-001" {
		t.Fatalf("ByKey(privilegedContainer) = %v, %v", m, ok)
	}
	if _, ok := ByID("CS-NOPE-999"); ok {
		t.Fatal("ByID returned a rule for an unknown ID")
	}
	if got := m.DocumentationURL(); got != docsBase+"cs-container-001" {
		t.Fatalf("DocumentationURL = %s", got)
	}
}
