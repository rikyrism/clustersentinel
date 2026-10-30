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
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvaluateRole(t *testing.T) {
	cases := []struct {
		name   string
		policy []rbacv1.PolicyRule
		// want maps rule ID to an evidence substring; missing IDs must not be reported.
		want map[string]string
	}{
		{"read-only role", []rbacv1.PolicyRule{
			{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
		}, nil},
		{"wildcard verbs", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}},
		}, map[string]string{IDWildcardRBAC: "rules[1] grants verbs [*] on resources [deployments]"}},
		{"wildcard resources", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}},
		}, map[string]string{IDWildcardRBAC: "resources [*]"}},
		{"wildcard api group only", []rbacv1.PolicyRule{
			{APIGroups: []string{"*"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
		}, nil},
		{"read secrets", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets", "configmaps"}, Verbs: []string{"get", "list"}},
		}, map[string]string{IDBroadRBAC: "rules[0] grants get,list on secrets"}},
		{"secrets restricted by name", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"app-tls"}, Verbs: []string{"get"}},
		}, nil},
		{"secrets create only", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}},
		}, nil},
		{"secrets in another api group", []rbacv1.PolicyRule{
			{APIGroups: []string{"example.com"}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		}, nil},
		{"exec through any api group", []rbacv1.PolicyRule{
			{APIGroups: []string{"*"}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
		}, map[string]string{IDBroadRBAC: "grants create on pods/exec"}},
		{"impersonate and escalate", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}},
			{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind", "escalate"}},
		}, map[string]string{IDBroadRBAC: "rules[0] grants impersonate on users; rules[1] grants escalate,bind on clusterroles"}},
		{"wildcard is not reported twice", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"*"}},
		}, map[string]string{IDWildcardRBAC: "on resources [secrets]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := EvaluateRole(tc.policy, strict())
			if len(vs) != len(tc.want) {
				t.Fatalf("got %+v, want %v", vs, tc.want)
			}
			for _, v := range vs {
				want, ok := tc.want[v.RuleID]
				if !ok || !strings.Contains(v.Evidence, want) {
					t.Fatalf("%s: evidence %q, want substring %q", v.RuleID, v.Evidence, want)
				}
				if v.Container != "" {
					t.Fatalf("%s: RBAC violation has container %q", v.RuleID, v.Container)
				}
			}
		})
	}
}

func TestEvaluateBinding(t *testing.T) {
	admin := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"}
	sa := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "ci", Namespace: "build"}
	masters := rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}

	vs := EvaluateBinding(admin, []rbacv1.Subject{masters, sa}, strict())
	if len(vs) != 1 || vs[0].Evidence != "roleRef is ClusterRole cluster-admin, bound to ServiceAccount build/ci" {
		t.Fatalf("got %+v", vs)
	}
	if vs := EvaluateBinding(admin, []rbacv1.Subject{masters}, strict()); len(vs) != 0 {
		t.Fatalf("installer group must not be reported, got %+v", vs)
	}
	if vs := EvaluateBinding(rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"}, []rbacv1.Subject{sa}, strict()); len(vs) != 0 {
		t.Fatalf("view binding reported: %+v", vs)
	}
	if vs := EvaluateBinding(rbacv1.RoleRef{Kind: "Role", Name: "cluster-admin"}, []rbacv1.Subject{sa}, strict()); len(vs) != 0 {
		t.Fatalf("a Role named cluster-admin is not the ClusterRole: %+v", vs)
	}
}

func TestIsBuiltInRBAC(t *testing.T) {
	for _, tc := range []struct {
		meta metav1.ObjectMeta
		want bool
	}{
		{metav1.ObjectMeta{Name: "cluster-admin", Labels: map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}}, true},
		{metav1.ObjectMeta{Name: "system:controller:deployment-controller"}, true},
		{metav1.ObjectMeta{Name: "my-operator"}, false},
	} {
		if got := IsBuiltInRBAC(&tc.meta); got != tc.want {
			t.Errorf("IsBuiltInRBAC(%s) = %v, want %v", tc.meta.Name, got, tc.want)
		}
	}
}

func TestEvaluateNamespace(t *testing.T) {
	if vs := EvaluateNamespace(true, false, strict()); len(vs) != 1 || vs[0].RuleID != IDMissingNetworkPolicy {
		t.Fatalf("got %+v", vs)
	}
	if vs := EvaluateNamespace(false, false, strict()); len(vs) != 0 {
		t.Fatalf("empty namespace reported: %+v", vs)
	}
	if vs := EvaluateNamespace(true, true, strict()); len(vs) != 0 {
		t.Fatalf("namespace with a NetworkPolicy reported: %+v", vs)
	}
	if vs := EvaluateNamespace(true, false, Settings{}); len(vs) != 0 {
		t.Fatalf("disabled rule reported: %+v", vs)
	}
}
