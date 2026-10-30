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

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

const ns = "default"

var k8s client.Client

// TestMain starts a real API server (envtest) with the generated CRDs installed.
// Run through "make test", which downloads the binaries and sets KUBEBUILDER_ASSETS.
func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		println("KUBEBUILDER_ASSETS is not set: run these tests with 'make test'")
		os.Exit(1)
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	scheme := runtime.NewScheme()
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if k8s, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		println("stopping envtest:", err.Error())
	}
	os.Exit(code)
}

func validFinding(name string) *securityv1alpha1.SecurityFinding {
	return &securityv1alpha1.SecurityFinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: securityv1alpha1.SecurityFindingSpec{
			RuleID:      "CS-CONTAINER-001",
			RuleVersion: 1,
			Severity:    securityv1alpha1.SeverityCritical,
			Resource: securityv1alpha1.AffectedResource{
				APIVersion: "apps/v1", Kind: "Deployment", Name: "payment-worker",
				Namespace: ns, UID: "0b6d8a8e-1111-2222-3333-444455556666", Container: "worker",
			},
			Title: "Privileged container",
		},
	}
}

func TestSecurityFindingAcceptsValidObjectAndStatus(t *testing.T) {
	ctx := context.Background()
	f := validFinding("valid")
	if err := k8s.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}
	now := metav1.Now()
	f.Status = securityv1alpha1.SecurityFindingStatus{
		State: securityv1alpha1.FindingOpen, FirstDetectedAt: &now, LastDetectedAt: &now,
	}
	if err := k8s.Status().Update(ctx, f); err != nil {
		t.Fatalf("status update: %v", err)
	}
	var got securityv1alpha1.SecurityFinding
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(f), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != securityv1alpha1.FindingOpen || got.Spec.Resource.Container != "worker" {
		t.Errorf("round trip lost data: %+v", got)
	}
}

func TestSecurityFindingRejectsInvalidValues(t *testing.T) {
	cases := map[string]func(*securityv1alpha1.SecurityFinding){
		"lowercase severity": func(f *securityv1alpha1.SecurityFinding) { f.Spec.Severity = "critical" },
		"malformed rule ID":  func(f *securityv1alpha1.SecurityFinding) { f.Spec.RuleID = "privileged" },
		"rule version 0":     func(f *securityv1alpha1.SecurityFinding) { f.Spec.RuleVersion = 0 },
		"empty kind":         func(f *securityv1alpha1.SecurityFinding) { f.Spec.Resource.Kind = "" },
		"empty uid":          func(f *securityv1alpha1.SecurityFinding) { f.Spec.Resource.UID = "" },
		"empty title":        func(f *securityv1alpha1.SecurityFinding) { f.Spec.Title = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := validFinding("invalid")
			mutate(f)
			err := k8s.Create(context.Background(), f)
			if !apierrors.IsInvalid(err) {
				t.Fatalf("expected an Invalid error, got %v", err)
			}
		})
	}
}

func TestSecurityPolicyDefaultsAndValidation(t *testing.T) {
	ctx := context.Background()
	p := &securityv1alpha1.SecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: ns}}
	if err := k8s.Create(ctx, p); err != nil {
		t.Fatalf("an empty policy must be accepted: %v", err)
	}
	if p.Spec.Profile != securityv1alpha1.ProfileRecommended || p.Spec.Remediation.Mode != securityv1alpha1.RemediationManual {
		t.Errorf("defaults not applied: %+v", p.Spec)
	}

	bad := &securityv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: ns},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Profile: "paranoid",
			Rules: securityv1alpha1.RuleOverrides{
				RunAsRoot: &securityv1alpha1.RuleConfig{Severity: "SEVERE"},
			},
			Remediation: securityv1alpha1.PolicyRemediation{Mode: "automatic"},
		},
	}
	err := k8s.Create(ctx, bad)
	if !apierrors.IsInvalid(err) {
		t.Fatalf("expected an Invalid error, got %v", err)
	}
	causes := map[string]bool{}
	for _, c := range err.(apierrors.APIStatus).Status().Details.Causes {
		causes[c.Field] = true
	}
	for _, field := range []string{"spec.profile", "spec.rules.runAsRoot.severity", "spec.remediation.mode"} {
		if !causes[field] {
			t.Errorf("no validation error for %s (got %v)", field, causes)
		}
	}
}

func TestSecurityReportStatusRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := &securityv1alpha1.SecurityReport{ObjectMeta: metav1.ObjectMeta{Name: securityv1alpha1.ClusterReportName, Namespace: ns}}
	if err := k8s.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	now := metav1.Now()
	r.Status = securityv1alpha1.SecurityReportStatus{
		ScannedResources: 12, OpenFindings: 3, LastScanTime: &now,
		BySeverity: securityv1alpha1.SeverityCounts{Critical: 1, High: 2},
	}
	if err := k8s.Status().Update(ctx, r); err != nil {
		t.Fatalf("status update: %v", err)
	}
	var got securityv1alpha1.SecurityReport
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(r), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.BySeverity.High != 2 || got.Status.LastScanTime == nil {
		t.Errorf("status lost: %+v", got.Status)
	}
}
