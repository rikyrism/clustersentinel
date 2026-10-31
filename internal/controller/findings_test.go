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
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

var (
	privilegedApp = rules.Violation{RuleID: rules.IDPrivileged, Severity: securityv1alpha1.SeverityCritical,
		Container: "app", Evidence: "spec.template.spec.containers[0].securityContext.privileged is true"}
	latestApp = rules.Violation{RuleID: rules.IDLatestImageTag, Severity: securityv1alpha1.SeverityMedium,
		Container: "app", Evidence: `spec.template.spec.containers[0].image is "web:latest"`}
)

// testClock is a settable clock, truncated to seconds like the times stored in the API.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestRecorder(refresh time.Duration) (*FindingRecorder, *testClock) {
	clock := &testClock{t: time.Now().Truncate(time.Second)}
	r := NewFindingRecorder(k8s, k8s, operatorNamespace, refresh)
	r.now = clock.now
	return r, clock
}

// deploymentRes describes a Deployment "web" in ns with a new UID on every call.
func deploymentRes(ns string) securityv1alpha1.AffectedResource {
	return securityv1alpha1.AffectedResource{APIVersion: "apps/v1", Kind: "Deployment", Namespace: ns, Name: "web", UID: unique("uid")}
}

// findingsOf lists the findings of key by rule ID.
func findingsOf(t *testing.T, ns, key string) map[string]securityv1alpha1.SecurityFinding {
	t.Helper()
	list := &securityv1alpha1.SecurityFindingList{}
	if err := k8s.List(ctx, list, client.InNamespace(ns), client.MatchingLabels{securityv1alpha1.LabelScanKey: scanKeyLabel(key)}); err != nil {
		t.Fatal(err)
	}
	out := map[string]securityv1alpha1.SecurityFinding{}
	for _, f := range list.Items {
		out[f.Spec.RuleID] = f
	}
	return out
}

func states(fs map[string]securityv1alpha1.SecurityFinding) map[string]securityv1alpha1.FindingState {
	out := map[string]securityv1alpha1.FindingState{}
	for id, f := range fs {
		out[id] = f.Status.State
	}
	return out
}

func versions(fs map[string]securityv1alpha1.SecurityFinding) map[string]string {
	out := map[string]string{}
	for id, f := range fs {
		out[id] = f.ResourceVersion
	}
	return out
}

func record(t *testing.T, r *FindingRecorder, key string, res securityv1alpha1.AffectedResource, vs ...rules.Violation) {
	t.Helper()
	if err := r.Record(ctx, key, res, vs); err != nil {
		t.Fatal(err)
	}
}

func TestFindingNames(t *testing.T) {
	res := securityv1alpha1.AffectedResource{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "shop", Name: "payment-worker", UID: "u1"}
	name := findingName(res, rules.IDPrivileged, "worker")
	if !strings.HasPrefix(name, "deployment-payment-worker-cs-container-001-") || len(name) != len("deployment-payment-worker-cs-container-001-")+8 {
		t.Fatalf("name = %q", name)
	}
	if findingName(res, rules.IDPrivileged, "worker") != name {
		t.Fatal("names are not deterministic")
	}
	other := res
	other.UID = "u2"
	for _, n := range []string{findingName(res, rules.IDPrivileged, "sidecar"), findingName(other, rules.IDPrivileged, "worker")} {
		if n == name {
			t.Fatalf("a different container or UID must give a different name, got %q twice", n)
		}
	}

	odd := securityv1alpha1.AffectedResource{Kind: "ClusterRole", Name: "Team:Admin.Role--" + strings.Repeat("x", 300), UID: "u3"}
	name = findingName(odd, rules.IDWildcardRBAC, "")
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 || !strings.HasPrefix(name, "clusterrole-team-admin-role-xxx") {
		t.Fatalf("name %q: %v", name, errs)
	}
	if strings.Contains(name, "--") {
		t.Fatalf("name %q has repeated dashes", name)
	}
}

// newFindings records a privileged container and a latest image on a new Deployment, with
// a refresh interval of one hour.
func newFindings(t *testing.T) (r *FindingRecorder, clock *testClock, ns, key string, res securityv1alpha1.AffectedResource) {
	t.Helper()
	ns = newNamespace(t, "findings")
	r, clock = newTestRecorder(time.Hour)
	res = deploymentRes(ns)
	key = "Deployment/" + ns + "/web"
	record(t, r, key, res, privilegedApp, latestApp)
	return r, clock, ns, key, res
}

func TestFindingCreated(t *testing.T) {
	_, clock, ns, key, res := newFindings(t)
	fs := findingsOf(t, ns, key)
	if got := states(fs); !maps.Equal(got, map[string]securityv1alpha1.FindingState{
		rules.IDPrivileged: securityv1alpha1.FindingOpen, rules.IDLatestImageTag: securityv1alpha1.FindingOpen,
	}) {
		t.Fatalf("states = %v", got)
	}
	f := fs[rules.IDPrivileged]
	want := securityv1alpha1.SecurityFindingSpec{
		RuleID: rules.IDPrivileged, RuleVersion: 1, Severity: securityv1alpha1.SeverityCritical,
		Resource: res, Title: "Privileged container", Evidence: privilegedApp.Evidence,
		Description:      rules.GuidanceFor(rules.IDPrivileged).Description,
		Recommendation:   rules.GuidanceFor(rules.IDPrivileged).Recommendation,
		DocumentationURL: "https://clustersentinel.web.id/docs/#cs-container-001",
	}
	want.Resource.Container = "app"
	if f.Spec != want {
		t.Fatalf("spec = %+v\nwant   %+v", f.Spec, want)
	}
	wantLabels := map[string]string{
		securityv1alpha1.LabelRuleID: rules.IDPrivileged, securityv1alpha1.LabelSeverity: "CRITICAL",
		securityv1alpha1.LabelState: "Open", securityv1alpha1.LabelResourceUID: res.UID,
		securityv1alpha1.LabelResourceKind: "Deployment", securityv1alpha1.LabelManagedBy: "clustersentinel",
		securityv1alpha1.LabelScanKey: scanKeyLabel(key),
	}
	if !maps.Equal(f.Labels, wantLabels) {
		t.Fatalf("labels = %v", f.Labels)
	}
	if refs := f.OwnerReferences; len(refs) != 1 || string(refs[0].UID) != res.UID || refs[0].Kind != "Deployment" ||
		refs[0].BlockOwnerDeletion != nil || refs[0].Controller != nil {
		t.Fatalf("owner references = %+v", refs)
	}
	if st := f.Status; st.FirstDetectedAt == nil || !st.FirstDetectedAt.Time.Equal(clock.t) ||
		st.LastDetectedAt == nil || st.ResolvedAt != nil {
		t.Fatalf("status = %+v", st)
	}
}

func TestFindingLifecycle(t *testing.T) {
	r, clock, ns, key, res := newFindings(t)
	first := findingsOf(t, ns, key)[rules.IDPrivileged].Status.FirstDetectedAt

	// The same result causes no write, even after a while (within the refresh).
	before := versions(findingsOf(t, ns, key))
	clock.advance(30 * time.Minute)
	record(t, r, key, res, privilegedApp, latestApp)
	if got := versions(findingsOf(t, ns, key)); !maps.Equal(got, before) {
		t.Fatalf("an unchanged result wrote: %v -> %v", before, got)
	}

	// A violation that disappears resolves its finding.
	record(t, r, key, res, latestApp)
	fs := findingsOf(t, ns, key)
	if f := fs[rules.IDPrivileged]; f.Status.State != securityv1alpha1.FindingResolved || f.Status.ResolvedAt == nil ||
		!f.Status.ResolvedAt.Time.Equal(clock.t) || f.Labels[securityv1alpha1.LabelState] != "Resolved" {
		t.Fatalf("resolved finding = %+v %v", f.Status, f.Labels)
	}
	if fs[rules.IDLatestImageTag].Status.State != securityv1alpha1.FindingOpen {
		t.Fatal("the remaining violation must stay open")
	}

	// It reopens when it comes back, keeping when it was first seen.
	clock.advance(time.Minute)
	record(t, r, key, res, privilegedApp, latestApp)
	f := findingsOf(t, ns, key)[rules.IDPrivileged]
	if f.Status.State != securityv1alpha1.FindingOpen || f.Status.ResolvedAt != nil || !f.Status.FirstDetectedAt.Equal(first) ||
		!f.Status.LastDetectedAt.Time.Equal(clock.t) || f.Labels[securityv1alpha1.LabelState] != "Open" {
		t.Fatalf("reopened finding = %+v %v", f.Status, f.Labels)
	}
}

func TestFindingRefreshAndSpecUpdate(t *testing.T) {
	r, clock, ns, key, res := newFindings(t)

	// After the refresh interval, lastDetectedAt is refreshed.
	clock.advance(2 * time.Hour)
	record(t, r, key, res, privilegedApp, latestApp)
	for id, f := range findingsOf(t, ns, key) {
		if !f.Status.LastDetectedAt.Time.Equal(clock.t) {
			t.Fatalf("%s: lastDetectedAt = %v, want %v", id, f.Status.LastDetectedAt, clock.t)
		}
	}

	// Evidence and severity changes update the spec and labels.
	changed := privilegedApp
	changed.Evidence, changed.Severity = "changed evidence", securityv1alpha1.SeverityHigh
	record(t, r, key, res, changed, latestApp)
	if f := findingsOf(t, ns, key)[rules.IDPrivileged]; f.Spec.Evidence != changed.Evidence ||
		f.Spec.Severity != securityv1alpha1.SeverityHigh || f.Labels[securityv1alpha1.LabelSeverity] != "HIGH" {
		t.Fatalf("finding = %+v %v", f.Spec, f.Labels)
	}
}

func TestFindingForget(t *testing.T) {
	_, _, ns, key, res := newFindings(t)

	// A unit that leaves the scan scope gets its findings resolved, also by a new process
	// that never saw it.
	restarted, _ := newTestRecorder(time.Hour)
	if err := restarted.Forget(ctx, key, false); err != nil {
		t.Fatal(err)
	}
	if got := states(findingsOf(t, ns, key)); !maps.Equal(got, map[string]securityv1alpha1.FindingState{
		rules.IDPrivileged: securityv1alpha1.FindingResolved, rules.IDLatestImageTag: securityv1alpha1.FindingResolved,
	}) {
		t.Fatalf("states after forget = %v", got)
	}
	if err := restarted.Forget(ctx, key, false); err != nil {
		t.Fatalf("forgetting again: %v", err)
	}

	// A deleted object's findings are left to the garbage collector.
	record(t, restarted, key, res, privilegedApp)
	before := versions(findingsOf(t, ns, key))
	if err := restarted.Forget(ctx, key, true); err != nil {
		t.Fatal(err)
	}
	if got := versions(findingsOf(t, ns, key)); !maps.Equal(got, before) || restarted.Len() != 0 {
		t.Fatalf("forgetting a deleted object wrote: %v -> %v", before, got)
	}
}

func TestFindingsOfARecreatedObject(t *testing.T) {
	ns := newNamespace(t, "recreated")
	r, _ := newTestRecorder(0)
	key := "Deployment/" + ns + "/web"
	old := deploymentRes(ns)
	record(t, r, key, old, privilegedApp)
	recreated := deploymentRes(ns)
	record(t, r, key, recreated, privilegedApp)

	list := &securityv1alpha1.SecurityFindingList{}
	if err := k8s.List(ctx, list, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	got := map[string]securityv1alpha1.FindingState{}
	for _, f := range list.Items {
		got[f.Spec.Resource.UID] = f.Status.State
	}
	if !maps.Equal(got, map[string]securityv1alpha1.FindingState{old.UID: "Resolved", recreated.UID: "Open"}) {
		t.Fatalf("findings by UID = %v", got)
	}
}

func TestFindingNamespaces(t *testing.T) {
	r, _ := newTestRecorder(0)
	ns := newNamespace(t, "netpol-finding")
	role := securityv1alpha1.AffectedResource{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: unique("Team:Admin"), UID: unique("uid")}
	namespace := securityv1alpha1.AffectedResource{APIVersion: "v1", Kind: "Namespace", Name: ns, UID: unique("uid")}
	wildcard := rules.Violation{RuleID: rules.IDWildcardRBAC, Severity: securityv1alpha1.SeverityHigh, Evidence: "rules[0] grants verbs [*]"}
	netpol := rules.Violation{RuleID: rules.IDMissingNetworkPolicy, Severity: securityv1alpha1.SeverityLow, Evidence: "no NetworkPolicy"}

	roleKey, nsKey := "ClusterRole/"+role.Name, "Namespace/"+ns
	record(t, r, roleKey, role, wildcard)
	record(t, r, nsKey, namespace, netpol)
	if fs := findingsOf(t, operatorNamespace, roleKey); len(fs) != 1 || fs[rules.IDWildcardRBAC].Spec.Resource.Name != role.Name {
		t.Fatalf("cluster-scoped findings must be in the operator namespace, got %v", fs)
	}
	if fs := findingsOf(t, ns, nsKey); len(fs) != 1 {
		t.Fatalf("namespace findings must be in that namespace, got %v", fs)
	}
}

func TestFindingRecorderLogsChangesOnly(t *testing.T) {
	var lines []string
	logger := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})
	lctx := log.IntoContext(context.Background(), logger)
	r, _ := newTestRecorder(0)
	ns := newNamespace(t, "logs")
	res := deploymentRes(ns)
	key := "Deployment/" + ns + "/web"

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.Record(lctx, key, res, nil)) // first clean result: V(1), hidden
	if len(lines) != 0 {
		t.Fatalf("first clean result logged at info: %v", lines)
	}
	must(r.Record(lctx, key, res, []rules.Violation{privilegedApp}))
	must(r.Record(lctx, key, res, []rules.Violation{privilegedApp})) // unchanged: not logged
	if len(lines) != 1 || !strings.Contains(lines[0], `"rules"=["CS-CONTAINER-001/app"]`) ||
		!strings.Contains(lines[0], `"resourceName"="web"`) {
		t.Fatalf("lines = %v", lines)
	}
	must(r.Forget(lctx, key, false))
	must(r.Forget(lctx, key, false)) // already forgotten: not logged
	if len(lines) != 2 || !strings.Contains(lines[1], "no longer analyzed") {
		t.Fatalf("lines = %v", lines)
	}
}

// expectFindings waits until the findings of key in ns have exactly the given states.
func expectFindings(t *testing.T, ns, key string, want map[string]securityv1alpha1.FindingState) {
	t.Helper()
	eventually(t, func() string {
		list := &securityv1alpha1.SecurityFindingList{}
		if err := k8s.List(ctx, list, client.InNamespace(ns), client.MatchingLabels{securityv1alpha1.LabelScanKey: scanKeyLabel(key)}); err != nil {
			return err.Error()
		}
		got := map[string]securityv1alpha1.FindingState{}
		for _, f := range list.Items {
			got[f.Spec.RuleID] = f.Status.State
		}
		if !maps.Equal(got, want) {
			return fmt.Sprintf("findings of %s = %v, want %v", key, got, want)
		}
		return ""
	})
}

// staleCache is a client whose cached reads have not seen any finding yet.
type staleCache struct{ client.Client }

func (staleCache) List(context.Context, client.ObjectList, ...client.ListOption) error { return nil }

func TestFindingCreateWithAStaleCache(t *testing.T) {
	_, _, ns, key, res := newFindings(t)
	stale := NewFindingRecorder(staleCache{k8s}, k8s, operatorNamespace, time.Hour)
	changed := privilegedApp
	changed.Evidence = "seen by a recorder whose cache is behind"
	if err := stale.Record(ctx, key, res, []rules.Violation{changed, latestApp}); err != nil {
		t.Fatalf("a finding the cache has not seen yet must be updated, not fail: %v", err)
	}
	if f := findingsOf(t, ns, key)[rules.IDPrivileged]; f.Spec.Evidence != changed.Evidence {
		t.Fatalf("evidence = %q", f.Spec.Evidence)
	}
}
