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

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rikyrism/clustersentinel/internal/rules"
)

var ctx = context.Background()

var labels = map[string]string{"app": "web"}

// hardenedPodSpec passes every workload rule of the strict profile.
func hardenedPodSpec() corev1.PodSpec {
	return corev1.PodSpec{
		ServiceAccountName:           "app",
		AutomountServiceAccountToken: new(false),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   new(true),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:  "app",
			Image: "registry.example.com/app:1.0.0",
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: new(false),
				ReadOnlyRootFilesystem:   new(true),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
		}},
	}
}

// privileged makes the first container privileged. The API server rejects privileged
// together with allowPrivilegeEscalation: false, so escalation is left unset and both
// rules fire.
func privileged(spec corev1.PodSpec) corev1.PodSpec {
	spec.Containers[0].SecurityContext.Privileged = new(true)
	spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
	return spec
}

var privilegedRules = []string{rules.IDPrivileged, rules.IDPrivilegeEscalation}

func deployment(ns, name string, spec corev1.PodSpec) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec},
		},
	}
}

func create(t *testing.T, objs ...client.Object) {
	t.Helper()
	for _, o := range objs {
		if err := k8s.Create(ctx, o); err != nil {
			t.Fatalf("creating %T %s: %v", o, o.GetName(), err)
		}
	}
}

// expectRules waits until key is recorded with exactly the given rule IDs.
func expectRules(t *testing.T, key string, want ...string) result {
	t.Helper()
	var got result
	eventually(t, func() string {
		r, ok := recorder.get(key)
		if !ok {
			return key + " was never recorded"
		}
		got = r
		if ids := ruleIDs(r.violations); !slices.Equal(ids, want) {
			return fmt.Sprintf("%s: rules %v, want %v", key, ids, want)
		}
		return ""
	})
	return got
}

func expectForgotten(t *testing.T, key string) {
	t.Helper()
	eventually(t, func() string {
		if _, ok := recorder.get(key); ok {
			return key + " is still recorded"
		}
		return ""
	})
}

func expectNeverRecorded(t *testing.T, key string) {
	t.Helper()
	consistently(t, 2*time.Second, func() string {
		if _, ok := recorder.get(key); ok {
			return key + " was recorded"
		}
		return ""
	})
}

func TestDeploymentLifecycle(t *testing.T) {
	ns := newNamespace(t, "deploy-lifecycle")
	d := deployment(ns, "web", privileged(hardenedPodSpec()))
	create(t, d)
	key := "Deployment/" + ns + "/web"

	r := expectRules(t, key, privilegedRules...)
	if r.res.Kind != "Deployment" || r.res.APIVersion != "apps/v1" || r.res.Name != "web" ||
		r.res.Namespace != ns || r.res.UID != string(d.UID) {
		t.Fatalf("affected resource = %+v", r.res)
	}
	if v := r.violations[0]; v.Container != "app" ||
		v.Evidence != "spec.template.spec.containers[0].securityContext.privileged is true" {
		t.Fatalf("violation = %+v", v)
	}

	// A status-only update must not reach the reconciler.
	records := r.records
	d.Status.ObservedGeneration = d.Generation
	d.Status.Replicas = 3
	if err := k8s.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	consistently(t, 2*time.Second, func() string {
		if r, _ := recorder.get(key); r.records != records {
			return fmt.Sprintf("status update caused a reconcile (%d records, was %d)", r.records, records)
		}
		return ""
	})

	// Fixing the template clears the violation.
	d.Spec.Template.Spec = hardenedPodSpec()
	if err := k8s.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	expectRules(t, key)

	if err := k8s.Delete(ctx, d); err != nil {
		t.Fatal(err)
	}
	expectForgotten(t, key)
}

func TestExcludedNamespaceIsNotAnalyzed(t *testing.T) {
	name := unique("web")
	create(t, deployment(excludedNamespace, name, privileged(hardenedPodSpec())))
	expectNeverRecorded(t, "Deployment/"+excludedNamespace+"/"+name)
}

func TestTemplateKinds(t *testing.T) {
	ns := newNamespace(t, "template-kinds")
	tmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: hardenedPodSpec()}
	tmpl.Spec.HostPID = true
	jobTmpl := *tmpl.DeepCopy()
	jobTmpl.Spec.RestartPolicy = corev1.RestartPolicyNever

	create(t,
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "db"},
			Spec: appsv1.StatefulSetSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: tmpl}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "agent"},
			Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: tmpl}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nightly"},
			Spec: batchv1.CronJobSpec{Schedule: "0 2 * * *",
				JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: jobTmpl}}}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "migrate"},
			Spec: batchv1.JobSpec{Template: jobTmpl}},
	)
	expectRules(t, "StatefulSet/"+ns+"/db", rules.IDHostPID)
	expectRules(t, "DaemonSet/"+ns+"/agent", rules.IDHostPID)
	expectRules(t, "Job/"+ns+"/migrate", rules.IDHostPID)
	cj := expectRules(t, "CronJob/"+ns+"/nightly", rules.IDHostPID)
	if ev := cj.violations[0].Evidence; ev != "spec.jobTemplate.spec.template.spec.hostPID is true" {
		t.Fatalf("CronJob evidence = %q", ev)
	}

	// A Job created by the CronJob is covered by the CronJob.
	owned := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nightly-123",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly",
			UID: types.UID(cj.res.UID), Controller: new(true)}}},
		Spec: batchv1.JobSpec{Template: jobTmpl}}
	create(t, owned)
	expectNeverRecorded(t, "Job/"+ns+"/nightly-123")
}

func TestReplicaSets(t *testing.T) {
	ns := newNamespace(t, "replicasets")
	spec := privileged(hardenedPodSpec())
	rs := func(name string, owner []metav1.OwnerReference) *appsv1.ReplicaSet {
		return &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owner},
			Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To[int32](2), Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec}},
		}
	}
	fromDeployment := rs("web-7d9f", []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web",
		UID: "11111111-1111-1111-1111-111111111111", Controller: new(true)}})
	fromRollout := rs("canary-5c4b", []metav1.OwnerReference{{APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout", Name: "canary",
		UID: "22222222-2222-2222-2222-222222222222", Controller: new(true)}})
	create(t, fromDeployment, fromRollout)

	key := "ReplicaSet/" + ns + "/canary-5c4b"
	expectRules(t, key, privilegedRules...)
	expectNeverRecorded(t, "ReplicaSet/"+ns+"/web-7d9f")

	// A scaled-down revision is no longer analyzed.
	fromRollout.Spec.Replicas = ptr.To[int32](0)
	if err := k8s.Update(ctx, fromRollout); err != nil {
		t.Fatal(err)
	}
	expectForgotten(t, key)
}

func pod(ns, name string, spec corev1.PodSpec, owner ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owner}, Spec: spec}
}

func TestPods(t *testing.T) {
	ns := newNamespace(t, "pods")
	create(t, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"}})

	// A standalone Pod is analyzed itself.
	create(t, pod(ns, "debug", privileged(hardenedPodSpec())))
	r := expectRules(t, "Pod/"+ns+"/debug", privilegedRules...)
	if ev := r.violations[0].Evidence; ev != "spec.containers[0].securityContext.privileged is true" {
		t.Fatalf("Pod evidence = %q", ev)
	}

	// A Pod of a ReplicaSet is covered by its template.
	create(t, pod(ns, "web-7d9f-abcde", privileged(hardenedPodSpec()), metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-7d9f", UID: "33333333-3333-3333-3333-333333333333", Controller: new(true)}))
	expectNeverRecorded(t, "Pod/"+ns+"/web-7d9f-abcde")

	// Pods of an unknown controller are one group, reported against the controller, with the
	// union of their violations.
	owner := metav1.OwnerReference{APIVersion: "example.com/v1", Kind: "Widget", Name: "widget",
		UID: "44444444-4444-4444-4444-444444444444", Controller: new(true)}
	hostPID := hardenedPodSpec()
	hostPID.HostPID = true
	a, b := pod(ns, "widget-0", privileged(hardenedPodSpec()), owner), pod(ns, "widget-1", hostPID, owner)
	create(t, a, b)
	key := "Pod/" + ns + "/" + groupPrefix + string(owner.UID)
	r = expectRules(t, key, rules.IDPrivileged, rules.IDPrivilegeEscalation, rules.IDHostPID)
	if r.res.Kind != "Widget" || r.res.APIVersion != "example.com/v1" || r.res.Name != "widget" ||
		r.res.UID != string(owner.UID) || r.res.Namespace != ns {
		t.Fatalf("group resource = %+v", r.res)
	}
	expectNeverRecorded(t, "Pod/"+ns+"/widget-0")

	if err := k8s.Delete(ctx, a, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	expectRules(t, key, rules.IDHostPID)
	if err := k8s.Delete(ctx, b, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	expectForgotten(t, key)
}

func TestServiceAccountChangeReanalyzesWorkloads(t *testing.T) {
	ns := newNamespace(t, "service-accounts")
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		AutomountServiceAccountToken: new(false)}
	spec := hardenedPodSpec()
	spec.AutomountServiceAccountToken = nil // inherit from the ServiceAccount
	create(t, sa, deployment(ns, "web", spec))
	key := "Deployment/" + ns + "/web"
	expectRules(t, key)

	sa.AutomountServiceAccountToken = new(true)
	if err := k8s.Update(ctx, sa); err != nil {
		t.Fatal(err)
	}
	r := expectRules(t, key, rules.IDServiceAccountToken)
	if !strings.Contains(r.violations[0].Evidence, `ServiceAccount "app" sets automountServiceAccountToken: true`) {
		t.Fatalf("evidence = %q", r.violations[0].Evidence)
	}
}

func TestRBAC(t *testing.T) {
	wide, builtIn, aggregated := unique("too-wide"), unique("system:test-builtin"), unique("aggregated")
	secrets, binding := unique("reads-secrets"), unique("ci-admin")
	wildcard := []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"get"}}}
	readSecrets := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}}
	create(t,
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: wide}, Rules: wildcard},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: builtIn}, Rules: wildcard},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: aggregated},
			AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"x": "y"}}}}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: secrets}, Rules: readSecrets},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: excludedNamespace, Name: secrets}, Rules: readSecrets},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: binding},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "ci", Namespace: "build"}}},
	)
	r := expectRules(t, "ClusterRole/"+wide, rules.IDWildcardRBAC)
	if r.res.Namespace != "" || r.res.APIVersion != rbacAPIVersion {
		t.Fatalf("ClusterRole resource = %+v", r.res)
	}
	expectRules(t, "Role/"+operatorNamespace+"/"+secrets, rules.IDBroadRBAC)
	expectRules(t, "ClusterRoleBinding/"+binding, rules.IDClusterAdminBinding)
	expectNeverRecorded(t, "ClusterRole/"+builtIn)
	expectNeverRecorded(t, "ClusterRole/"+aggregated)
	expectNeverRecorded(t, "Role/"+excludedNamespace+"/"+secrets)
}

func TestNamespaceNetworkPolicy(t *testing.T) {
	ns := newNamespace(t, "netpol")
	key := "Namespace/" + ns
	expectRules(t, key) // no Pods yet

	create(t,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"}},
		pod(ns, "web", hardenedPodSpec()),
	)
	expectRules(t, key, rules.IDMissingNetworkPolicy)

	create(t, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default-deny"},
		Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}})
	expectRules(t, key)
}
