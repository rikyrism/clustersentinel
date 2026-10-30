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
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/config"
	"github.com/rikyrism/clustersentinel/internal/manager"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

const (
	operatorNamespace = "clustersentinel-system"
	excludedNamespace = "excluded"
)

var (
	k8s      client.Client
	recorder = &fakeRecorder{results: map[string]result{}}
)

// result is what the fake recorder keeps per key.
type result struct {
	res        securityv1alpha1.AffectedResource
	violations []rules.Violation
	records    int
}

type fakeRecorder struct {
	mu      sync.Mutex
	results map[string]result
}

func (f *fakeRecorder) Record(_ context.Context, key string, res securityv1alpha1.AffectedResource, vs []rules.Violation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[key] = result{res: res, violations: vs, records: f.results[key].records + 1}
}

func (f *fakeRecorder) Forget(_ context.Context, key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.results, key)
}

func (f *fakeRecorder) get(key string) (result, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.results[key]
	return r, ok
}

// TestMain starts a real API server (envtest) and the controllers with the strict profile,
// so every rule runs. envtest has no controller-manager: Deployments create no Pods, and
// Pods are never scheduled, which the tests rely on.
func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		println("KUBEBUILDER_ASSETS is not set: run these tests with 'make test'")
		os.Exit(1)
	}
	ctrl.SetLogger(zap.New(zap.WriteTo(io.Discard)))
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if k8s, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
		panic(err)
	}

	opCfg := config.Default()
	opCfg.Scanner.Profile = securityv1alpha1.ProfileStrict
	opCfg.Scanner.Namespaces.Exclude = []string{"kube-system", excludedNamespace}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:   manager.CacheOptions(opCfg, operatorNamespace),
	})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := Setup(ctx, mgr, &Scanner{
		Client:                  mgr.GetClient(),
		Recorder:                recorder,
		Namespaces:              opCfg.Scanner.Namespaces,
		Settings:                opCfg.Scanner.RuleSettings(),
		MaxConcurrentReconciles: 2,
	}); err != nil {
		panic(err)
	}
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()
	for _, ns := range []string{operatorNamespace, excludedNamespace} {
		if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			panic(err)
		}
	}

	code := m.Run()
	cancel()
	if err := env.Stop(); err != nil {
		println("stopping envtest:", err.Error())
	}
	os.Exit(code)
}

// eventually polls cond until it returns "" or the timeout passes, then fails with the
// last message.
func eventually(t *testing.T, cond func() string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		msg := cond()
		if msg == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// consistently fails if cond returns a message at any point during d.
func consistently(t *testing.T, d time.Duration, cond func() string) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if msg := cond(); msg != "" {
			t.Fatal(msg)
		}
	}
}

// ruleIDs returns the distinct rule IDs of a result, in order.
func ruleIDs(vs []rules.Violation) []string {
	var ids []string
	for _, v := range vs {
		if !slices.Contains(ids, v.RuleID) {
			ids = append(ids, v.RuleID)
		}
	}
	return ids
}

var runs atomic.Int32

// unique suffixes name so that tests can run repeatedly in one process (go test -count=N),
// where objects from earlier runs still exist: envtest has no namespace controller to
// delete them.
func unique(name string) string { return fmt.Sprintf("%s-%d", name, runs.Add(1)) }

// newNamespace creates a namespace for one test and returns its unique name.
func newNamespace(t *testing.T, name string) string {
	t.Helper()
	name = unique(name)
	if err := k8s.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		t.Fatal(err)
	}
	return name
}
