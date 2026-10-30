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
	"hash/fnv"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// Recorder receives the result of every analysis. Keys are stable per analyzed unit
// (for example "Deployment/app/web"); a key is forgotten when its unit disappears or
// leaves the scan scope.
type Recorder interface {
	Record(ctx context.Context, key string, res securityv1alpha1.AffectedResource, violations []rules.Violation)
	Forget(ctx context.Context, key string)
}

// LogRecorder logs analysis results when they change. It is the Phase 2 recorder; the
// SecurityFinding writer replaces it in Phase 3 and keeps the same change detection, so
// unchanged results never cause writes.
type LogRecorder struct {
	mu   sync.Mutex
	last map[string]recorded
}

type recorded struct {
	fingerprint uint64
	violations  int
}

// NewLogRecorder returns an empty LogRecorder.
func NewLogRecorder() *LogRecorder { return &LogRecorder{last: map[string]recorded{}} }

// Record logs the result if it differs from the previous one for key. A first clean
// result is logged at V(1) only, so a healthy cluster does not log every workload at start.
func (r *LogRecorder) Record(ctx context.Context, key string, res securityv1alpha1.AffectedResource, vs []rules.Violation) {
	fp := fingerprint(res, vs)
	r.mu.Lock()
	prev, seen := r.last[key]
	r.last[key] = recorded{fingerprint: fp, violations: len(vs)}
	r.mu.Unlock()
	if seen && prev.fingerprint == fp {
		return
	}
	logger := log.FromContext(ctx)
	if !seen && len(vs) == 0 {
		logger = logger.V(1)
	}
	logger.Info("Analysis result changed",
		"resourceKind", res.Kind, "resourceNamespace", res.Namespace, "resourceName", res.Name,
		"violations", len(vs), "rules", violationLabels(vs))
}

// Forget drops key, logging it when it still had violations.
func (r *LogRecorder) Forget(ctx context.Context, key string) {
	r.mu.Lock()
	prev, seen := r.last[key]
	delete(r.last, key)
	r.mu.Unlock()
	if seen && prev.violations > 0 {
		log.FromContext(ctx).Info("Resource no longer analyzed", "key", key)
	}
}

// Len returns the number of analyzed units.
func (r *LogRecorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.last)
}

// violationLabels renders violations as "CS-CONTAINER-001/app" (rule/container).
func violationLabels(vs []rules.Violation) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.RuleID
		if v.Container != "" {
			out[i] += "/" + v.Container
		}
	}
	return out
}

// fingerprint identifies a result: the resource identity and every violation field.
func fingerprint(res securityv1alpha1.AffectedResource, vs []rules.Violation) uint64 {
	h := fnv.New64a()
	write := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	write(res.APIVersion)
	write(res.Kind)
	write(res.Namespace)
	write(res.Name)
	write(res.UID)
	for _, v := range vs {
		write(v.RuleID)
		write(string(v.Severity))
		write(v.Container)
		write(v.Evidence)
	}
	return h.Sum64()
}
