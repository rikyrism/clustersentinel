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

// SeverityCounts counts open findings per severity.
type SeverityCounts struct {
	Critical int32 `json:"critical"`
	High     int32 `json:"high"`
	Medium   int32 `json:"medium"`
	Low      int32 `json:"low"`
	Info     int32 `json:"info"`
}

// ClusterReportName is the name of the single report, kept in the operator's namespace.
const ClusterReportName = "cluster"

// SecurityReportSpec is empty: the report is created and maintained by the operator.
type SecurityReportSpec struct{}

// SecurityReportStatus holds the cluster-wide summary. It deliberately does not copy
// findings; per-namespace summaries are computed by the CLI from the findings themselves.
// The operator updates it at most once per minute.
type SecurityReportStatus struct {
	// scannedResources is the number of resources analyzed in the last scan.
	// +optional
	ScannedResources int32 `json:"scannedResources"`

	// openFindings is the number of findings in state Open.
	// +optional
	OpenFindings int32 `json:"openFindings"`

	// resolvedFindings is the number of findings in state Resolved still retained.
	// +optional
	ResolvedFindings int32 `json:"resolvedFindings"`

	// bySeverity counts open findings per severity.
	// +optional
	BySeverity SeverityCounts `json:"bySeverity"`

	// lastScanTime is when the last scan of this scope completed.
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// conditions: "ScannerHealthy" reports whether the last scan completed without errors.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=secr;sreport,categories=clustersentinel
// +kubebuilder:printcolumn:name="Open",type=integer,JSONPath=`.status.openFindings`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.bySeverity.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.bySeverity.high`
// +kubebuilder:printcolumn:name="Last Scan",type=date,JSONPath=`.status.lastScanTime`

// SecurityReport summarizes ClusterSentinel's findings for the whole cluster. There is one,
// named "cluster", in the operator's namespace.
type SecurityReport struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec is empty; the report is maintained by the operator
	// +optional
	Spec SecurityReportSpec `json:"spec,omitzero"`

	// status holds the summary
	// +optional
	Status SecurityReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecurityReportList contains a list of SecurityReport
type SecurityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecurityReport{}, &SecurityReportList{})
		return nil
	})
}
