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

// Package rules holds ClusterSentinel's built-in security rules.
package rules

import (
	"slices"
	"strings"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

// Scope is the kind of object a rule evaluates.
type Scope string

const (
	ScopeWorkload  Scope = "Workload"
	ScopeRBAC      Scope = "RBAC"
	ScopeNamespace Scope = "Namespace"
)

// Metadata describes a rule independently of its detection logic.
type Metadata struct {
	// ID is the stable rule identifier, e.g. CS-CONTAINER-001.
	ID string
	// Key is the camelCase name used in SecurityPolicy and Helm values.
	Key string
	// Version increases when detection logic changes meaningfully.
	Version int32
	Name    string
	Scope   Scope
	// DefaultSeverity applies unless a policy overrides it.
	DefaultSeverity securityv1alpha1.Severity
	// Profiles lists the built-in profiles that enable the rule.
	Profiles []securityv1alpha1.Profile
}

const docsBase = "https://clustersentinel.web.id/docs/#"

// DocumentationURL returns the rule's section in the website documentation.
func (m Metadata) DocumentationURL() string { return docsBase + strings.ToLower(m.ID) }

var (
	basicUp       = []securityv1alpha1.Profile{securityv1alpha1.ProfileBasic, securityv1alpha1.ProfileRecommended, securityv1alpha1.ProfileStrict}
	recommendedUp = []securityv1alpha1.Profile{securityv1alpha1.ProfileRecommended, securityv1alpha1.ProfileStrict}
	strictOnly    = []securityv1alpha1.Profile{securityv1alpha1.ProfileStrict}
)

// Rule IDs. They are stable: a rule keeps its ID for life, even when its logic changes.
const (
	IDPrivileged             = "CS-CONTAINER-001"
	IDPrivilegeEscalation    = "CS-CONTAINER-002"
	IDRunAsRoot              = "CS-CONTAINER-003"
	IDReadOnlyRootFilesystem = "CS-CONTAINER-004"
	IDDropCapabilities       = "CS-CONTAINER-005"
	IDDangerousCapabilities  = "CS-CONTAINER-006"
	IDSeccompProfile         = "CS-CONTAINER-007"
	IDHostNetwork            = "CS-CONTAINER-008"
	IDHostPID                = "CS-CONTAINER-009"
	IDHostIPC                = "CS-CONTAINER-010"
	IDLatestImageTag         = "CS-IMAGE-001"
	IDImplicitImageTag       = "CS-IMAGE-002"
	IDServiceAccountToken    = "CS-SA-001"
	IDDefaultServiceAccount  = "CS-SA-002"
	IDWildcardRBAC           = "CS-RBAC-001"
	IDClusterAdminBinding    = "CS-RBAC-002"
	IDBroadRBAC              = "CS-RBAC-003"
	IDMissingNetworkPolicy   = "CS-NETWORK-001"
)

// Catalog lists every built-in rule in documentation order.
var Catalog = []Metadata{
	{ID: IDPrivileged, Key: "privilegedContainer", Version: 1, Name: "Privileged container", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityCritical, Profiles: basicUp},
	{ID: IDPrivilegeEscalation, Key: "allowPrivilegeEscalation", Version: 1, Name: "Privilege escalation allowed", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: basicUp},
	{ID: IDRunAsRoot, Key: "runAsRoot", Version: 1, Name: "Container may run as root", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityMedium, Profiles: recommendedUp},
	{ID: IDReadOnlyRootFilesystem, Key: "readOnlyRootFilesystem", Version: 1, Name: "Writable root filesystem", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityLow, Profiles: recommendedUp},
	{ID: IDDropCapabilities, Key: "dropCapabilities", Version: 1, Name: "Linux capabilities not dropped", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityLow, Profiles: recommendedUp},
	{ID: IDDangerousCapabilities, Key: "dangerousCapabilities", Version: 1, Name: "Dangerous Linux capabilities added", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: basicUp},
	{ID: IDSeccompProfile, Key: "seccompProfile", Version: 1, Name: "Missing seccomp profile", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityLow, Profiles: recommendedUp},
	{ID: IDHostNetwork, Key: "hostNetwork", Version: 1, Name: "Host network enabled", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: basicUp},
	{ID: IDHostPID, Key: "hostPID", Version: 1, Name: "Host PID namespace enabled", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: basicUp},
	{ID: IDHostIPC, Key: "hostIPC", Version: 1, Name: "Host IPC namespace enabled", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: basicUp},
	{ID: IDLatestImageTag, Key: "latestImageTag", Version: 1, Name: "Image uses the latest tag", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityMedium, Profiles: recommendedUp},
	{ID: IDImplicitImageTag, Key: "implicitImageTag", Version: 1, Name: "Image has no tag", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityMedium, Profiles: recommendedUp},
	{ID: IDServiceAccountToken, Key: "serviceAccountToken", Version: 1, Name: "Service account token automounted", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityLow, Profiles: recommendedUp},
	{ID: IDDefaultServiceAccount, Key: "defaultServiceAccount", Version: 1, Name: "Workload uses the default ServiceAccount", Scope: ScopeWorkload, DefaultSeverity: securityv1alpha1.SeverityInfo, Profiles: strictOnly},
	{ID: IDWildcardRBAC, Key: "wildcardRBAC", Version: 1, Name: "Wildcard RBAC permissions", Scope: ScopeRBAC, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: recommendedUp},
	{ID: IDClusterAdminBinding, Key: "clusterAdminBinding", Version: 1, Name: "cluster-admin bound to a subject", Scope: ScopeRBAC, DefaultSeverity: securityv1alpha1.SeverityHigh, Profiles: basicUp},
	{ID: IDBroadRBAC, Key: "broadRBAC", Version: 1, Name: "Broad sensitive permissions", Scope: ScopeRBAC, DefaultSeverity: securityv1alpha1.SeverityMedium, Profiles: recommendedUp},
	{ID: IDMissingNetworkPolicy, Key: "missingNetworkPolicy", Version: 1, Name: "Namespace has no NetworkPolicy", Scope: ScopeNamespace, DefaultSeverity: securityv1alpha1.SeverityLow, Profiles: strictOnly},
}

// ByKey returns the rule with the given policy key.
func ByKey(key string) (Metadata, bool) {
	for _, m := range Catalog {
		if m.Key == key {
			return m, true
		}
	}
	return Metadata{}, false
}

// ByID returns the rule with the given ID.
func ByID(id string) (Metadata, bool) {
	for _, m := range Catalog {
		if m.ID == id {
			return m, true
		}
	}
	return Metadata{}, false
}

// EnabledIn reports whether the rule is part of profile p. The custom profile enables nothing
// by itself.
func (m Metadata) EnabledIn(p securityv1alpha1.Profile) bool {
	return slices.Contains(m.Profiles, p)
}
