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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Profile selects a predefined set of enabled rules and severities.
// +kubebuilder:validation:Enum=basic;recommended;strict;custom
type Profile string

const (
	// ProfileBasic enables only the rules with the highest signal (privileged, host namespaces,
	// privilege escalation, cluster-admin bindings).
	ProfileBasic Profile = "basic"
	// ProfileRecommended enables all workload and RBAC rules except the NetworkPolicy heuristic.
	ProfileRecommended Profile = "recommended"
	// ProfileStrict enables every rule.
	ProfileStrict Profile = "strict"
	// ProfileCustom enables only the rules explicitly enabled in spec.rules.
	ProfileCustom Profile = "custom"
)

// RemediationMode controls how remediation is offered. Only manual exists in the MVP:
// ClusterSentinel never mutates workloads.
// +kubebuilder:validation:Enum=manual
type RemediationMode string

const RemediationManual RemediationMode = "manual"

// RuleConfig overrides the profile for a single rule.
type RuleConfig struct {
	// enabled turns the rule on or off. Unset keeps the profile's choice.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// severity overrides the rule's default severity. Unset keeps the default.
	// +optional
	Severity Severity `json:"severity,omitempty"`
}

// RuleOverrides holds per-rule overrides keyed by a stable, readable rule key.
// Each key maps to one rule ID (see https://clustersentinel.rikyrism.my.id/docs/#rules).
type RuleOverrides struct {
	// CS-CONTAINER-001
	// +optional
	PrivilegedContainer *RuleConfig `json:"privilegedContainer,omitempty"`
	// CS-CONTAINER-002
	// +optional
	AllowPrivilegeEscalation *RuleConfig `json:"allowPrivilegeEscalation,omitempty"`
	// CS-CONTAINER-003
	// +optional
	RunAsRoot *RuleConfig `json:"runAsRoot,omitempty"`
	// CS-CONTAINER-004
	// +optional
	ReadOnlyRootFilesystem *RuleConfig `json:"readOnlyRootFilesystem,omitempty"`
	// CS-CONTAINER-005
	// +optional
	DropCapabilities *RuleConfig `json:"dropCapabilities,omitempty"`
	// CS-CONTAINER-006
	// +optional
	DangerousCapabilities *RuleConfig `json:"dangerousCapabilities,omitempty"`
	// CS-CONTAINER-007
	// +optional
	SeccompProfile *RuleConfig `json:"seccompProfile,omitempty"`
	// CS-CONTAINER-008
	// +optional
	HostNetwork *RuleConfig `json:"hostNetwork,omitempty"`
	// CS-CONTAINER-009
	// +optional
	HostPID *RuleConfig `json:"hostPID,omitempty"`
	// CS-CONTAINER-010
	// +optional
	HostIPC *RuleConfig `json:"hostIPC,omitempty"`
	// CS-IMAGE-001
	// +optional
	LatestImageTag *RuleConfig `json:"latestImageTag,omitempty"`
	// CS-IMAGE-002
	// +optional
	ImplicitImageTag *RuleConfig `json:"implicitImageTag,omitempty"`
	// CS-SA-001
	// +optional
	ServiceAccountToken *RuleConfig `json:"serviceAccountToken,omitempty"`
	// CS-SA-002
	// +optional
	DefaultServiceAccount *RuleConfig `json:"defaultServiceAccount,omitempty"`
	// CS-NETWORK-001
	// +optional
	MissingNetworkPolicy *RuleConfig `json:"missingNetworkPolicy,omitempty"`
}

// PolicyNotifications controls notifications for findings governed by this policy.
type PolicyNotifications struct {
	// enabled allows notifications for findings in this namespace. Delivery also requires
	// a notification channel configured on the operator (Helm values).
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
}

// PolicyRemediation controls remediation behavior.
type PolicyRemediation struct {
	// mode is always manual in this version.
	// +kubebuilder:default=manual
	// +optional
	Mode RemediationMode `json:"mode,omitempty"`
}

// SecurityPolicySpec configures which checks run for workloads in the policy's namespace.
//
// Precedence: a SecurityPolicy in a namespace overrides the operator-wide defaults from
// Helm values. If a namespace has several SecurityPolicies, the oldest one (by
// creationTimestamp, then name) is used and the others report Active=False.
// RBAC checks (CS-RBAC-*) are governed by operator-wide defaults only, because
// ClusterRoles and ClusterRoleBindings do not belong to a namespace.
type SecurityPolicySpec struct {
	// profile selects the base rule set.
	// +kubebuilder:default=recommended
	// +optional
	Profile Profile `json:"profile,omitempty"`

	// rules overrides the profile per rule.
	// +optional
	Rules RuleOverrides `json:"rules,omitempty"`

	// remediation controls remediation behavior.
	// +kubebuilder:default={}
	// +optional
	Remediation PolicyRemediation `json:"remediation,omitempty"`

	// notifications controls notifications for this namespace.
	// +kubebuilder:default={}
	// +optional
	Notifications PolicyNotifications `json:"notifications,omitempty"`
}

// SecurityPolicyStatus defines the observed state of SecurityPolicy.
type SecurityPolicyStatus struct {
	// observedGeneration is the most recent generation processed by the operator.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions: "Active" is True when this policy is the one in effect for its namespace.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=secpol;spol,categories=clustersentinel
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Active",type=string,JSONPath=`.status.conditions[?(@.type=="Active")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecurityPolicy configures ClusterSentinel's checks for one namespace.
type SecurityPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines which checks run
	// +kubebuilder:default={}
	// +optional
	Spec SecurityPolicySpec `json:"spec,omitzero"`

	// status defines the observed state of SecurityPolicy
	// +optional
	Status SecurityPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecurityPolicyList contains a list of SecurityPolicy
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecurityPolicy{}, &SecurityPolicyList{})
		return nil
	})
}
