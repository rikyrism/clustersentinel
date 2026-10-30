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
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

func TestLogRecorderLogsChangesOnly(t *testing.T) {
	var lines []string
	logger := funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})
	lctx := log.IntoContext(context.Background(), logger)

	r := NewLogRecorder()
	res := securityv1alpha1.AffectedResource{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "app", Name: "web", UID: "u1"}
	bad := []rules.Violation{{RuleID: rules.IDPrivileged, Severity: securityv1alpha1.SeverityCritical, Container: "app", Evidence: "x"}}

	r.Record(lctx, "a", res, nil) // first clean result: V(1), hidden
	if len(lines) != 0 {
		t.Fatalf("first clean result logged at info: %v", lines)
	}
	r.Record(lctx, "a", res, bad)
	r.Record(lctx, "a", res, bad) // unchanged: not logged
	if len(lines) != 1 || !strings.Contains(lines[0], `"rules"=["CS-CONTAINER-001/app"]`) ||
		!strings.Contains(lines[0], `"resourceName"="web"`) {
		t.Fatalf("lines = %v", lines)
	}

	res.UID = "u2" // recreated with the same name: a new result
	r.Record(lctx, "a", res, bad)
	if len(lines) != 2 {
		t.Fatalf("a new UID must be logged, lines = %v", lines)
	}

	r.Forget(lctx, "a")
	r.Forget(lctx, "a") // already gone: not logged
	if len(lines) != 3 || !strings.Contains(lines[2], "no longer analyzed") || r.Len() != 0 {
		t.Fatalf("lines = %v, len = %d", lines, r.Len())
	}
}
