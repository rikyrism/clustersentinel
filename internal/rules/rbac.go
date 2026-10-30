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
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IsBuiltInRBAC reports whether an RBAC object is part of Kubernetes itself (the default
// roles and bindings created by the API server, and "system:" objects). Those are not
// evaluated: they are expected to be powerful and users cannot meaningfully change them.
func IsBuiltInRBAC(obj metav1.Object) bool {
	return obj.GetLabels()["kubernetes.io/bootstrapping"] == "rbac-defaults" ||
		strings.HasPrefix(obj.GetName(), "system:")
}

// EvaluateRole runs the enabled Role/ClusterRole rules against a list of policy rules.
func EvaluateRole(policy []rbacv1.PolicyRule, s Settings) []Violation {
	var out []Violation
	if s.Enabled(IDWildcardRBAC) {
		if ev := wildcardEvidence(policy); ev != "" {
			out = append(out, Violation{RuleID: IDWildcardRBAC, Severity: s.Severity(IDWildcardRBAC), Evidence: ev})
		}
	}
	if s.Enabled(IDBroadRBAC) {
		if ev := broadEvidence(policy); ev != "" {
			out = append(out, Violation{RuleID: IDBroadRBAC, Severity: s.Severity(IDBroadRBAC), Evidence: ev})
		}
	}
	return out
}

func isWildcard(r rbacv1.PolicyRule) bool {
	return slices.Contains(r.Verbs, rbacv1.VerbAll) || slices.Contains(r.Resources, rbacv1.ResourceAll)
}

func wildcardEvidence(policy []rbacv1.PolicyRule) string {
	var parts []string
	for i, r := range policy {
		if isWildcard(r) {
			parts = append(parts, fmt.Sprintf("rules[%d] grants verbs [%s] on resources [%s]",
				i, strings.Join(r.Verbs, ","), strings.Join(r.Resources, ",")))
		}
	}
	return strings.Join(parts, "; ")
}

// sensitivePermission is a permission that leads to secrets, code execution on Pods or
// nodes, or more permissions.
type sensitivePermission struct {
	group     string
	resources []string
	verbs     []string
}

const verbCreate = "create"

var sensitivePermissions = []sensitivePermission{
	{"", []string{"secrets"}, []string{"get", "list", "watch"}},
	{"", []string{"pods/exec", "pods/attach"}, []string{verbCreate}},
	{"", []string{"nodes/proxy"}, []string{"get", verbCreate}},
	{"", []string{"serviceaccounts/token"}, []string{verbCreate}},
	{"", []string{"users", "groups", "serviceaccounts"}, []string{"impersonate"}},
	{rbacv1.GroupName, []string{"roles", "clusterroles"}, []string{"escalate", "bind"}},
}

// broadEvidence reports sensitive permissions granted without a resourceNames restriction.
// Rules with wildcards are left to the wildcard rule, so one grant is reported once.
func broadEvidence(policy []rbacv1.PolicyRule) string {
	var parts []string
	for i, r := range policy {
		if isWildcard(r) || len(r.ResourceNames) > 0 {
			continue
		}
		for _, sp := range sensitivePermissions {
			if !slices.Contains(r.APIGroups, sp.group) && !slices.Contains(r.APIGroups, rbacv1.APIGroupAll) {
				continue
			}
			for _, res := range sp.resources {
				if !slices.Contains(r.Resources, res) {
					continue
				}
				var verbs []string
				for _, v := range sp.verbs {
					if slices.Contains(r.Verbs, v) {
						verbs = append(verbs, v)
					}
				}
				if len(verbs) > 0 {
					parts = append(parts, fmt.Sprintf("rules[%d] grants %s on %s", i, strings.Join(verbs, ","), res))
				}
			}
		}
	}
	return strings.Join(parts, "; ")
}

// installerAdminGroups are groups that cluster installers bind to cluster-admin as the
// break-glass administrator group. Bindings to them are expected and not reported.
var installerAdminGroups = []string{"system:masters", "kubeadm:cluster-admins"}

// EvaluateBinding runs the enabled RoleBinding/ClusterRoleBinding rules.
func EvaluateBinding(roleRef rbacv1.RoleRef, subjects []rbacv1.Subject, s Settings) []Violation {
	if !s.Enabled(IDClusterAdminBinding) || roleRef.Kind != "ClusterRole" || roleRef.Name != "cluster-admin" {
		return nil
	}
	var names []string
	for _, sub := range subjects {
		if sub.Kind == rbacv1.GroupKind && slices.Contains(installerAdminGroups, sub.Name) {
			continue
		}
		name := sub.Name
		if sub.Namespace != "" {
			name = sub.Namespace + "/" + sub.Name
		}
		names = append(names, sub.Kind+" "+name)
	}
	if len(names) == 0 {
		return nil
	}
	return []Violation{{
		RuleID:   IDClusterAdminBinding,
		Severity: s.Severity(IDClusterAdminBinding),
		Evidence: "roleRef is ClusterRole cluster-admin, bound to " + strings.Join(names, ", "),
	}}
}

// EvaluateNamespace runs the enabled namespace rules. Namespaces without Pods are not
// reported: a NetworkPolicy there would protect nothing.
func EvaluateNamespace(hasPods, hasNetworkPolicy bool, s Settings) []Violation {
	if !s.Enabled(IDMissingNetworkPolicy) || !hasPods || hasNetworkPolicy {
		return nil
	}
	return []Violation{{
		RuleID:   IDMissingNetworkPolicy,
		Severity: s.Severity(IDMissingNetworkPolicy),
		Evidence: "the namespace has Pods and no NetworkPolicy",
	}}
}
