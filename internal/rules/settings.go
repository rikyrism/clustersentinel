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
	"slices"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

// Override changes one rule on top of a profile. A nil Enabled keeps the profile's choice;
// an empty Severity keeps the rule's default severity.
type Override struct {
	Enabled  *bool
	Severity securityv1alpha1.Severity
}

// Settings is the effective rule set: which rules run and at which severity.
// The zero value enables nothing.
type Settings struct {
	// severity holds the effective severity of every enabled rule, keyed by rule ID.
	severity map[string]securityv1alpha1.Severity
}

// NewSettings applies overrides (keyed by rule key) to a profile. Unknown keys are ignored;
// configuration validation reports them.
func NewSettings(profile securityv1alpha1.Profile, overrides map[string]Override) Settings {
	s := Settings{severity: make(map[string]securityv1alpha1.Severity, len(Catalog))}
	for _, m := range Catalog {
		enabled := m.EnabledIn(profile)
		sev := m.DefaultSeverity
		if o, ok := overrides[m.Key]; ok {
			if o.Enabled != nil {
				enabled = *o.Enabled
			}
			if o.Severity != "" {
				sev = o.Severity
			}
		}
		if enabled {
			s.severity[m.ID] = sev
		}
	}
	return s
}

// Enabled reports whether the rule with the given ID runs.
func (s Settings) Enabled(id string) bool {
	_, ok := s.severity[id]
	return ok
}

// Severity returns the effective severity of an enabled rule.
func (s Settings) Severity(id string) securityv1alpha1.Severity { return s.severity[id] }

// AnyEnabled reports whether at least one of the given rules runs.
func (s Settings) AnyEnabled(ids ...string) bool {
	return slices.ContainsFunc(ids, s.Enabled)
}

// EnabledIDs returns the IDs of the enabled rules in catalog order.
func (s Settings) EnabledIDs() []string {
	ids := make([]string, 0, len(s.severity))
	for _, m := range Catalog {
		if s.Enabled(m.ID) {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// IDsInScope returns the IDs of every catalog rule with the given scope.
func IDsInScope(scope Scope) []string {
	var ids []string
	for _, m := range Catalog {
		if m.Scope == scope {
			ids = append(ids, m.ID)
		}
	}
	return ids
}
