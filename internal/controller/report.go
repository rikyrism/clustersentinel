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
	"errors"
	"fmt"
	"math"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/config"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

const (
	// ConditionScannerHealthy is the SecurityReport condition about the last interval.
	ConditionScannerHealthy = "ScannerHealthy"
	// defaultReportInterval is how often the report is computed and retention applied.
	defaultReportInterval = time.Minute
	// sweepPageSize bounds each page of the startup sweep.
	sweepPageSize = 500
)

// Janitor keeps the findings tidy and the cluster report current. It runs on the leader
// only:
//   - at start, it resolves open findings that no controller will touch again: findings
//     of rules that are now disabled, and of namespaces that are no longer scanned;
//   - every Interval, it deletes Resolved findings older than Retention and updates the
//     SecurityReport, writing only when something in it changed.
type Janitor struct {
	// Client reads findings from the cache and writes.
	Client client.Client
	// Reader reads from the API server. The startup sweep uses it to see findings in
	// namespaces the cache does not hold.
	Reader client.Reader
	// Namespace is the operator's namespace, where the report lives.
	Namespace  string
	Settings   rules.Settings
	Namespaces config.Namespaces
	// Retention is how long Resolved findings are kept; zero keeps them.
	Retention time.Duration
	// Rescan is the rescan interval. The report's lastScanTime alone does not cause a
	// write until it is this old (ten minutes when rescans are off).
	Rescan   time.Duration
	Interval time.Duration
	Recorder *FindingRecorder

	now func() time.Time
}

// NeedLeaderElection makes the Janitor run on the leader only, like the controllers.
func (j *Janitor) NeedLeaderElection() bool { return true }

// Start runs the startup sweep, then the periodic work until ctx ends.
func (j *Janitor) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("janitor")
	ctx = log.IntoContext(ctx, logger)
	if n, err := j.Sweep(ctx); err != nil {
		logger.Error(err, "Startup sweep failed; findings it missed stay open until their resource is analyzed")
	} else if n > 0 {
		logger.Info("Resolved findings of disabled rules or unscanned namespaces", "count", n)
	}
	interval := j.Interval
	if interval <= 0 {
		interval = defaultReportInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := j.Tick(ctx); err != nil {
			logger.Error(err, "Updating the report or applying retention failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (j *Janitor) clock() time.Time {
	if j.now != nil {
		return j.now()
	}
	return time.Now()
}

// stale reports whether an open finding will never be updated by a controller again.
func (j *Janitor) stale(f *securityv1alpha1.SecurityFinding) bool {
	if !j.Settings.Enabled(f.Spec.RuleID) {
		return true
	}
	res := f.Spec.Resource
	switch {
	case res.Namespace != "":
		return !j.Namespaces.NamespaceSelected(res.Namespace)
	case res.APIVersion == "v1" && res.Kind == "Namespace":
		return !j.Namespaces.NamespaceSelected(res.Name)
	default:
		return false
	}
}

// Sweep resolves open findings that no controller will update again and returns how many
// it resolved. It reads every namespace from the API server, page by page.
func (j *Janitor) Sweep(ctx context.Context) (int, error) {
	now := j.clock()
	resolved := 0
	var errs []error
	opts := []client.ListOption{
		client.MatchingLabels{
			securityv1alpha1.LabelManagedBy: securityv1alpha1.ManagedByValue,
			securityv1alpha1.LabelState:     string(securityv1alpha1.FindingOpen),
		},
		client.Limit(sweepPageSize),
	}
	for cont := ""; ; {
		list := &securityv1alpha1.SecurityFindingList{}
		if err := j.Reader.List(ctx, list, append(opts, client.Continue(cont))...); err != nil {
			return resolved, err
		}
		for i := range list.Items {
			if f := &list.Items[i]; j.stale(f) {
				if err := resolve(ctx, j.Client, f, now); err != nil {
					errs = append(errs, err)
					continue
				}
				resolved++
			}
		}
		if cont = list.Continue; cont == "" {
			return resolved, errors.Join(errs...)
		}
	}
}

// Tick applies retention and updates the report. Only findings the operator manages are
// counted or deleted; findings created by hand are left alone.
func (j *Janitor) Tick(ctx context.Context) error {
	now := j.clock()
	list := &securityv1alpha1.SecurityFindingList{}
	if err := j.Client.List(ctx, list, client.UnsafeDisableDeepCopy,
		client.MatchingLabels{securityv1alpha1.LabelManagedBy: securityv1alpha1.ManagedByValue}); err != nil {
		return err
	}
	var errs []error
	var status securityv1alpha1.SecurityReportStatus
	for i := range list.Items {
		f := &list.Items[i]
		if f.Status.State != securityv1alpha1.FindingResolved {
			status.OpenFindings++
			count(&status.BySeverity, f.Spec.Severity)
			continue
		}
		if j.Retention > 0 && f.Status.ResolvedAt != nil && now.Sub(f.Status.ResolvedAt.Time) >= j.Retention {
			if err := j.Client.Delete(ctx, f); client.IgnoreNotFound(err) != nil {
				errs = append(errs, fmt.Errorf("deleting resolved finding %s/%s: %w", f.Namespace, f.Name, err))
				status.ResolvedFindings++
			}
			continue
		}
		status.ResolvedFindings++
	}
	errs = append(errs, j.updateReport(ctx, status, now))
	return errors.Join(errs...)
}

func count(c *securityv1alpha1.SeverityCounts, s securityv1alpha1.Severity) {
	switch s {
	case securityv1alpha1.SeverityCritical:
		c.Critical++
	case securityv1alpha1.SeverityHigh:
		c.High++
	case securityv1alpha1.SeverityMedium:
		c.Medium++
	case securityv1alpha1.SeverityLow:
		c.Low++
	case securityv1alpha1.SeverityInfo:
		c.Info++
	}
}

// updateReport writes the report status when its counts or condition changed, or when its
// lastScanTime is older than the rescan interval. The report is created if missing.
func (j *Janitor) updateReport(ctx context.Context, status securityv1alpha1.SecurityReportStatus, now time.Time) error {
	report := &securityv1alpha1.SecurityReport{}
	key := client.ObjectKey{Namespace: j.Namespace, Name: securityv1alpha1.ClusterReportName}
	if err := j.Client.Get(ctx, key, report); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		report = &securityv1alpha1.SecurityReport{ObjectMeta: metav1.ObjectMeta{
			Name: key.Name, Namespace: key.Namespace,
			Labels: map[string]string{securityv1alpha1.LabelManagedBy: securityv1alpha1.ManagedByValue},
		}}
		if err := j.Client.Create(ctx, report); err != nil {
			return fmt.Errorf("creating the report: %w", err)
		}
	}

	lastRecord, failures := j.Recorder.takeStats()
	status.ScannedResources = int32(min(j.Recorder.Len(), math.MaxInt32))
	status.LastScanTime = report.Status.LastScanTime
	if !lastRecord.IsZero() {
		staleAfter := j.Rescan
		if staleAfter <= 0 {
			staleAfter = 10 * time.Minute
		}
		if status.LastScanTime == nil || lastRecord.Sub(status.LastScanTime.Time) >= staleAfter {
			status.LastScanTime = &metav1.Time{Time: lastRecord}
		}
	}
	status.Conditions = append([]metav1.Condition(nil), report.Status.Conditions...)
	healthy := metav1.Condition{
		Type: ConditionScannerHealthy, Status: metav1.ConditionTrue,
		Reason: "Scanning", Message: "Findings are written as resources are analyzed.",
	}
	if failures > 0 {
		healthy.Status, healthy.Reason = metav1.ConditionFalse, "WriteFailed"
		healthy.Message = fmt.Sprintf("%d writes of findings failed since the last update; they are retried.", failures)
	}
	healthy.LastTransitionTime = metav1.NewTime(now)
	meta.SetStatusCondition(&status.Conditions, healthy)

	if equality.Semantic.DeepEqual(report.Status, status) {
		return nil
	}
	orig := report.DeepCopy()
	report.Status = status
	if err := j.Client.Status().Patch(ctx, report, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("updating the report: %w", err)
	}
	return nil
}
