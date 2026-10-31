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
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// Recorder receives the result of every analysis. Keys are stable per analyzed unit
// (for example "Deployment/app/web").
type Recorder interface {
	// Record stores the violations found on res. An error makes the reconcile retry.
	Record(ctx context.Context, key string, res securityv1alpha1.AffectedResource, violations []rules.Violation) error
	// Forget is called when a unit is no longer analyzed. deleted means its object is
	// gone, so Kubernetes deletes its findings through their owner reference; otherwise
	// (scaled to zero, adopted by another controller, out of scope) they are resolved.
	Forget(ctx context.Context, key string, deleted bool) error
}

// FindingRecorder writes analysis results as SecurityFindings. It remembers a fingerprint
// of the last result per key, so an unchanged result causes no API call at all, except
// for the lastDetectedAt refresh once per Refresh.
type FindingRecorder struct {
	// Client reads findings from the cache and writes them.
	Client client.Client
	// Reader reads from the API server, for a finding the cache has not seen yet.
	Reader client.Reader
	// Namespace receives findings about cluster-scoped objects other than namespaces.
	Namespace string
	// Refresh is how often lastDetectedAt of an unchanged finding is refreshed. Zero
	// never refreshes it.
	Refresh time.Duration

	now func() time.Time

	mu         sync.Mutex
	last       map[string]recorded
	lastRecord time.Time
	failures   int
}

type recorded struct {
	fingerprint uint64
	synced      time.Time
	violations  int
}

// NewFindingRecorder returns a FindingRecorder with no remembered results.
func NewFindingRecorder(c client.Client, reader client.Reader, namespace string, refresh time.Duration) *FindingRecorder {
	return &FindingRecorder{
		Client: c, Reader: reader, Namespace: namespace, Refresh: refresh, now: time.Now, last: map[string]recorded{},
	}
}

// Record writes the findings for key when its result changed or the refresh is due. A
// changed result is also logged; a first clean result only at V(1), so a healthy cluster
// does not log every workload at start.
func (r *FindingRecorder) Record(ctx context.Context, key string, res securityv1alpha1.AffectedResource, vs []rules.Violation) error {
	fp := fingerprint(res, vs)
	now := r.now()
	r.mu.Lock()
	prev, seen := r.last[key]
	r.mu.Unlock()
	unchanged := seen && prev.fingerprint == fp
	if unchanged && (r.Refresh <= 0 || now.Sub(prev.synced) < r.Refresh) {
		r.mu.Lock()
		r.lastRecord = now
		r.mu.Unlock()
		return nil
	}
	if err := r.sync(ctx, key, res, vs, now); err != nil {
		r.mu.Lock()
		r.failures++
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	r.last[key] = recorded{fingerprint: fp, synced: now, violations: len(vs)}
	r.lastRecord = now
	r.mu.Unlock()
	if unchanged {
		return nil
	}
	logger := log.FromContext(ctx)
	if !seen && len(vs) == 0 {
		logger = logger.V(1)
	}
	logger.Info("Analysis result changed",
		"resourceKind", res.Kind, "resourceNamespace", res.Namespace, "resourceName", res.Name,
		"violations", len(vs), "rules", violationLabels(vs))
	return nil
}

// Forget drops key. Unless its object was deleted, its open findings are resolved; this
// also runs for keys never seen in this process, so findings left by a previous run are
// resolved too.
func (r *FindingRecorder) Forget(ctx context.Context, key string, deleted bool) error {
	r.mu.Lock()
	prev, seen := r.last[key]
	delete(r.last, key)
	r.mu.Unlock()
	if !deleted {
		if err := r.resolveKey(ctx, key); err != nil {
			r.mu.Lock()
			r.failures++
			r.mu.Unlock()
			return err
		}
	}
	if seen && prev.violations > 0 {
		log.FromContext(ctx).Info("Resource no longer analyzed", "key", key, "deleted", deleted)
	}
	return nil
}

// Len returns the number of analyzed units.
func (r *FindingRecorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.last)
}

// takeStats returns when a result was last recorded and how many writes failed since the
// previous call.
func (r *FindingRecorder) takeStats() (lastRecord time.Time, failures int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lastRecord, failures = r.lastRecord, r.failures
	r.failures = 0
	return lastRecord, failures
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
