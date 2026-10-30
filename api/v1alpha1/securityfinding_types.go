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

// FindingState is the lifecycle state of a finding.
// +kubebuilder:validation:Enum=Open;Resolved
type FindingState string

const (
	FindingOpen     FindingState = "Open"
	FindingResolved FindingState = "Resolved"
)

// AffectedResource identifies the Kubernetes object a finding is about.
type AffectedResource struct {
	// apiVersion of the affected object, e.g. apps/v1.
	// +kubebuilder:validation:MinLength=1
	// +required
	APIVersion string `json:"apiVersion"`

	// kind of the affected object, e.g. Deployment.
	// +kubebuilder:validation:MinLength=1
	// +required
	Kind string `json:"kind"`

	// name of the affected object.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// namespace of the affected object; empty for cluster-scoped objects.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// uid of the affected object. A recreated object has a new UID and gets new findings.
	// +kubebuilder:validation:MinLength=1
	// +required
	UID string `json:"uid"`

	// container is the affected container, for container-level rules.
	// +optional
	Container string `json:"container,omitempty"`
}

// SecurityFindingSpec describes one rule violation on one resource (and container).
// The spec is written by the operator; edits by users are overwritten on the next scan.
type SecurityFindingSpec struct {
	// ruleID is the stable identifier of the rule, e.g. CS-CONTAINER-001.
	// +kubebuilder:validation:Pattern=`^CS-[A-Z]+-[0-9]{3}$`
	// +required
	RuleID string `json:"ruleID"`

	// ruleVersion increases when the rule's detection logic changes meaningfully.
	// +kubebuilder:validation:Minimum=1
	// +required
	RuleVersion int32 `json:"ruleVersion"`

	// severity is the effective severity after policy overrides.
	// +required
	Severity Severity `json:"severity"`

	// resource identifies the affected object.
	// +required
	Resource AffectedResource `json:"resource"`

	// title is a short human-readable summary.
	// +kubebuilder:validation:MinLength=1
	// +required
	Title string `json:"title"`

	// description explains what was detected.
	// +optional
	Description string `json:"description,omitempty"`

	// evidence is the offending configuration path and value, e.g.
	// "spec.template.spec.containers[worker].securityContext.privileged=true".
	// It never contains Secret data or environment variable values.
	// +optional
	Evidence string `json:"evidence,omitempty"`

	// recommendation describes how to address the finding.
	// +optional
	Recommendation string `json:"recommendation,omitempty"`

	// documentationURL links to the rule's documentation.
	// +optional
	DocumentationURL string `json:"documentationURL,omitempty"`
}

// SecurityFindingStatus is the lifecycle of the finding.
type SecurityFindingStatus struct {
	// state is Open while the issue is present and Resolved after it disappears.
	// +optional
	State FindingState `json:"state,omitempty"`

	// firstDetectedAt is when the issue was first seen on this resource.
	// +optional
	FirstDetectedAt *metav1.Time `json:"firstDetectedAt,omitempty"`

	// lastDetectedAt is when a scan last confirmed the issue. It is refreshed at most
	// once per rescan interval to limit API writes.
	// +optional
	LastDetectedAt *metav1.Time `json:"lastDetectedAt,omitempty"`

	// resolvedAt is when the issue was no longer detected.
	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`

	// notifiedSeverity is the severity last announced to notification channels.
	// It makes notification deduplication survive operator restarts.
	// +optional
	NotifiedSeverity Severity `json:"notifiedSeverity,omitempty"`

	// notifiedState is the state last announced to notification channels.
	// +optional
	NotifiedState FindingState `json:"notifiedState,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=secf;sfinding,categories=clustersentinel
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Rule",type=string,JSONPath=`.spec.ruleID`
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.spec.resource.kind`
// +kubebuilder:printcolumn:name="Resource",type=string,JSONPath=`.spec.resource.name`
// +kubebuilder:printcolumn:name="Container",type=string,JSONPath=`.spec.resource.container`,priority=1
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Last Seen",type=date,JSONPath=`.status.lastDetectedAt`

// SecurityFinding records one insecure configuration detected by ClusterSentinel.
type SecurityFinding struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec describes the finding
	// +required
	Spec SecurityFindingSpec `json:"spec"`

	// status tracks the finding's lifecycle
	// +optional
	Status SecurityFindingStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecurityFindingList contains a list of SecurityFinding
type SecurityFindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityFinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecurityFinding{}, &SecurityFindingList{})
		return nil
	})
}
