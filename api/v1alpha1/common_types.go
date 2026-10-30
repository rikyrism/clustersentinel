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

package v1alpha1

// Severity is the impact level assigned to a finding.
// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW;INFO
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Severities lists every severity from most to least severe.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// Rank orders severities: CRITICAL is 4, INFO is 0, unknown values are -1.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return -1
	}
}

// IsValid reports whether s is one of the defined severities.
func (s Severity) IsValid() bool { return s.Rank() >= 0 }

// Common label keys set on objects owned by ClusterSentinel.
const (
	LabelManagedBy    = "app.kubernetes.io/managed-by"
	ManagedByValue    = "clustersentinel"
	LabelRuleID       = "security.clustersentinel.io/rule-id"
	LabelSeverity     = "security.clustersentinel.io/severity"
	LabelState        = "security.clustersentinel.io/state"
	LabelResourceKind = "security.clustersentinel.io/resource-kind"
	LabelResourceUID  = "security.clustersentinel.io/resource-uid"
)
