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
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/config"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

func TestJanitorSweepResolvesFindingsNoControllerWillTouch(t *testing.T) {
	scanned, unscanned := newNamespace(t, "sweep-scanned"), newNamespace(t, "sweep-unscanned")
	r, _ := newTestRecorder(0)
	inScope, outOfScope := "Deployment/"+scanned+"/web", "Deployment/"+unscanned+"/web"
	record(t, r, inScope, deploymentRes(scanned), privilegedApp, latestApp)
	record(t, r, outOfScope, deploymentRes(unscanned), privilegedApp)

	// The basic profile does not include the latest-tag rule.
	j := &Janitor{
		Client: k8s, Reader: k8s, Namespace: operatorNamespace,
		Settings:   rules.NewSettings(securityv1alpha1.ProfileBasic, nil),
		Namespaces: config.Namespaces{Exclude: []string{unscanned}},
		Recorder:   r,
	}
	if _, err := j.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := states(findingsOf(t, scanned, inScope)); got[rules.IDPrivileged] != securityv1alpha1.FindingOpen ||
		got[rules.IDLatestImageTag] != securityv1alpha1.FindingResolved {
		t.Fatalf("in scope: %v", got)
	}
	if got := states(findingsOf(t, unscanned, outOfScope)); got[rules.IDPrivileged] != securityv1alpha1.FindingResolved {
		t.Fatalf("unscanned namespace: %v", got)
	}
}

// janitorSetup records a Deployment that was recreated: two resolved findings of the old
// object and one open finding of the new one. The report goes to its own namespace.
func janitorSetup(t *testing.T) (j *Janitor, r *FindingRecorder, clock *testClock, ns, key string, res securityv1alpha1.AffectedResource) {
	t.Helper()
	ns = newNamespace(t, "janitor")
	reportNS := newNamespace(t, "janitor-report")
	r, clock = newTestRecorder(0)
	key = "Deployment/" + ns + "/web"
	record(t, r, key, deploymentRes(ns), privilegedApp, latestApp)
	res = deploymentRes(ns) // recreated with a new UID: both earlier findings resolve
	record(t, r, key, res, latestApp)
	j = &Janitor{
		Client: k8s, Reader: k8s, Namespace: reportNS,
		Settings: rules.NewSettings(securityv1alpha1.ProfileStrict, nil), Retention: 24 * time.Hour,
		Rescan: time.Hour, Recorder: r, now: clock.now,
	}
	return j, r, clock, ns, key, res
}

func (j *Janitor) report(t *testing.T) *securityv1alpha1.SecurityReport {
	t.Helper()
	rep := &securityv1alpha1.SecurityReport{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: j.Namespace, Name: securityv1alpha1.ClusterReportName}, rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func (j *Janitor) tick(t *testing.T) {
	t.Helper()
	if err := j.Tick(ctx); err != nil {
		t.Fatal(err)
	}
}

// managedCounts counts the operator's findings in the API. Other tests write findings too,
// so the expected report comes from the API, not from this test.
func managedCounts(t *testing.T) securityv1alpha1.SecurityReportStatus {
	t.Helper()
	list := &securityv1alpha1.SecurityFindingList{}
	if err := k8s.List(ctx, list, client.MatchingLabels{securityv1alpha1.LabelManagedBy: securityv1alpha1.ManagedByValue}); err != nil {
		t.Fatal(err)
	}
	var s securityv1alpha1.SecurityReportStatus
	for _, f := range list.Items {
		if f.Status.State == securityv1alpha1.FindingResolved {
			s.ResolvedFindings++
			continue
		}
		s.OpenFindings++
		count(&s.BySeverity, f.Spec.Severity)
	}
	return s
}

func healthy(rep *securityv1alpha1.SecurityReport) *metav1.Condition {
	return meta.FindStatusCondition(rep.Status.Conditions, ConditionScannerHealthy)
}

func TestJanitorReport(t *testing.T) {
	j, r, clock, _, key, res := janitorSetup(t)
	want := managedCounts(t)
	j.tick(t)
	rep := j.report(t)
	if st := rep.Status; st.OpenFindings != want.OpenFindings || st.ResolvedFindings != want.ResolvedFindings ||
		st.BySeverity != want.BySeverity || st.ScannedResources != 1 ||
		st.LastScanTime == nil || !st.LastScanTime.Time.Equal(clock.t) {
		t.Fatalf("report = %+v, want counts %+v", st, want)
	}
	if c := healthy(rep); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("conditions = %+v", rep.Status.Conditions)
	}

	// Nothing changed: no write, even though the clock moved (within the rescan interval).
	clock.advance(time.Minute)
	record(t, r, key, res, latestApp)
	j.tick(t)
	if got := j.report(t); got.ResourceVersion != rep.ResourceVersion {
		t.Fatalf("an unchanged report was written: %+v", got.Status)
	}

	// Failed writes turn the condition False until a clean interval.
	r.mu.Lock()
	r.failures = 2
	r.mu.Unlock()
	j.tick(t)
	if c := healthy(j.report(t)); c == nil || c.Status != metav1.ConditionFalse || c.Reason != "WriteFailed" {
		t.Fatalf("condition after failures = %+v", c)
	}
	j.tick(t)
	if c := healthy(j.report(t)); c.Status != metav1.ConditionTrue {
		t.Fatalf("condition after a clean interval = %+v", c)
	}
}

func TestJanitorRetention(t *testing.T) {
	j, _, clock, ns, key, _ := janitorSetup(t)

	// A finding created by hand (like the sample in config/samples) is never deleted.
	manual := &securityv1alpha1.SecurityFinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "manual"},
		Spec: securityv1alpha1.SecurityFindingSpec{
			RuleID: rules.IDPrivileged, RuleVersion: 1, Severity: securityv1alpha1.SeverityCritical, Title: "manual",
			Resource: securityv1alpha1.AffectedResource{APIVersion: "apps/v1", Kind: "Deployment", Name: "x", UID: "manual"},
		},
	}
	if err := k8s.Create(ctx, manual); err != nil {
		t.Fatal(err)
	}
	manual.Status = securityv1alpha1.SecurityFindingStatus{State: securityv1alpha1.FindingResolved, ResolvedAt: &metav1.Time{Time: clock.t}}
	if err := k8s.Status().Update(ctx, manual); err != nil {
		t.Fatal(err)
	}

	list := &securityv1alpha1.SecurityFindingList{}
	if err := k8s.List(ctx, list, client.InNamespace(ns), client.MatchingLabels{
		securityv1alpha1.LabelScanKey: scanKeyLabel(key), securityv1alpha1.LabelState: "Resolved",
	}); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("want 2 resolved findings, have %d", len(list.Items))
	}

	j.tick(t) // within the retention: nothing is deleted
	clock.advance(25 * time.Hour)
	j.tick(t)
	for _, f := range list.Items {
		err := k8s.Get(ctx, client.ObjectKeyFromObject(&f), &securityv1alpha1.SecurityFinding{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("resolved finding %s still exists after the retention: %v", f.Name, err)
		}
	}
	if got := states(findingsOf(t, ns, key)); got[rules.IDLatestImageTag] != securityv1alpha1.FindingOpen {
		t.Fatalf("open finding must stay: %v", got)
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(manual), &securityv1alpha1.SecurityFinding{}); err != nil {
		t.Fatalf("a finding created by hand must not be deleted: %v", err)
	}
}
