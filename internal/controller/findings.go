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
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// Finding names are <kind>-<resource name>-<rule id>-<hash>, the hash covering the
// resource UID, rule and container. They are deterministic, so a rescan updates a finding
// instead of creating a duplicate, and a recreated object (new UID) gets new findings.
const (
	maxKindInName     = 30
	maxResourceInName = 40
)

// findingName returns the name of the finding for one rule and container on res.
func findingName(res securityv1alpha1.AffectedResource, ruleID, container string) string {
	sum := sha256.Sum256([]byte(res.UID + "\x00" + ruleID + "\x00" + container))
	parts := []string{
		nameSegment(res.Kind, maxKindInName), nameSegment(res.Name, maxResourceInName),
		strings.ToLower(ruleID), hex.EncodeToString(sum[:4]),
	}
	return strings.Join(strings.FieldsFunc(strings.Join(parts, "-"), func(r rune) bool { return r == '-' }), "-")
}

// nameSegment lowercases s, replaces anything but letters and digits with "-" and cuts it
// to max characters. RBAC names may contain ":" or upper case; object names may not.
func nameSegment(s string, maxLen int) string {
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			b[i] = '-'
		}
	}
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	return string(b)
}

// scanKeyLabel is the LabelScanKey value of a key. Keys contain "/" and ":", which label
// values cannot.
func scanKeyLabel(key string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return fmt.Sprintf("%016x", h.Sum64())
}

// findingNamespace is where the findings about res live: the object's namespace, the
// namespace itself for namespace rules, and the operator's namespace for other
// cluster-scoped objects.
func (r *FindingRecorder) findingNamespace(res securityv1alpha1.AffectedResource) string {
	switch {
	case res.Namespace != "":
		return res.Namespace
	case res.APIVersion == "v1" && res.Kind == "Namespace":
		return res.Name
	default:
		return r.Namespace
	}
}

// desired builds the findings for one result. Violations of the same rule and container
// are merged, so names never collide.
func (r *FindingRecorder) desired(key string, res securityv1alpha1.AffectedResource, vs []rules.Violation) []*securityv1alpha1.SecurityFinding {
	ns := r.findingNamespace(res)
	var out []*securityv1alpha1.SecurityFinding
	byName := map[string]*securityv1alpha1.SecurityFinding{}
	for _, v := range vs {
		name := findingName(res, v.RuleID, v.Container)
		if f, ok := byName[name]; ok {
			f.Spec.Evidence += "; " + v.Evidence
			continue
		}
		meta, _ := rules.ByID(v.RuleID)
		guide := rules.GuidanceFor(v.RuleID)
		target := res
		target.Container = v.Container
		f := &securityv1alpha1.SecurityFinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels: map[string]string{
					securityv1alpha1.LabelManagedBy:    securityv1alpha1.ManagedByValue,
					securityv1alpha1.LabelRuleID:       v.RuleID,
					securityv1alpha1.LabelSeverity:     string(v.Severity),
					securityv1alpha1.LabelState:        string(securityv1alpha1.FindingOpen),
					securityv1alpha1.LabelResourceKind: res.Kind,
					securityv1alpha1.LabelResourceUID:  res.UID,
					securityv1alpha1.LabelScanKey:      scanKeyLabel(key),
				},
				// The owner reference lets Kubernetes delete the finding with its object, even
				// when the operator is not running. It does not block the owner's deletion.
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: res.APIVersion, Kind: res.Kind, Name: res.Name, UID: types.UID(res.UID),
				}},
			},
			Spec: securityv1alpha1.SecurityFindingSpec{
				RuleID:           v.RuleID,
				RuleVersion:      max(meta.Version, 1),
				Severity:         v.Severity,
				Resource:         target,
				Title:            cmp.Or(meta.Name, v.RuleID),
				Description:      guide.Description,
				Evidence:         v.Evidence,
				Recommendation:   guide.Recommendation,
				DocumentationURL: meta.DocumentationURL(),
			},
		}
		byName[name] = f
		out = append(out, f)
	}
	return out
}

// sync makes the findings of key match vs: missing ones are created, changed ones updated,
// reappearing ones reopened and ones no longer reported resolved.
func (r *FindingRecorder) sync(ctx context.Context, key string, res securityv1alpha1.AffectedResource, vs []rules.Violation, now time.Time) error {
	list := &securityv1alpha1.SecurityFindingList{}
	if err := r.Client.List(ctx, list, client.InNamespace(r.findingNamespace(res)),
		client.MatchingLabels{securityv1alpha1.LabelScanKey: scanKeyLabel(key)}); err != nil {
		return err
	}
	existing := make(map[string]*securityv1alpha1.SecurityFinding, len(list.Items))
	for i := range list.Items {
		existing[list.Items[i].Name] = &list.Items[i]
	}
	var errs []error
	for _, want := range r.desired(key, res, vs) {
		if cur, ok := existing[want.Name]; ok {
			delete(existing, want.Name)
			errs = append(errs, r.update(ctx, cur, want, now))
			continue
		}
		errs = append(errs, r.create(ctx, want, now))
	}
	for _, cur := range existing {
		errs = append(errs, resolve(ctx, r.Client, cur, now))
	}
	return errors.Join(errs...)
}

// resolveKey resolves every open finding of key, in any namespace.
func (r *FindingRecorder) resolveKey(ctx context.Context, key string) error {
	list := &securityv1alpha1.SecurityFindingList{}
	if err := r.Client.List(ctx, list, client.MatchingLabels{
		securityv1alpha1.LabelScanKey: scanKeyLabel(key),
		securityv1alpha1.LabelState:   string(securityv1alpha1.FindingOpen),
	}); err != nil {
		return err
	}
	now := r.now()
	var errs []error
	for i := range list.Items {
		errs = append(errs, resolve(ctx, r.Client, &list.Items[i], now))
	}
	return errors.Join(errs...)
}

// create writes a new finding, then its status: the status subresource ignores the status
// sent with a create. When the cache has not seen a finding created moments ago, Create
// fails with AlreadyExists and the finding is read from the API server and updated.
func (r *FindingRecorder) create(ctx context.Context, f *securityv1alpha1.SecurityFinding, now time.Time) error {
	if err := r.Client.Create(ctx, f); err != nil {
		if apierrors.IsAlreadyExists(err) && r.Reader != nil {
			cur := &securityv1alpha1.SecurityFinding{}
			if err := r.Reader.Get(ctx, client.ObjectKeyFromObject(f), cur); err != nil {
				return fmt.Errorf("reading finding %s/%s: %w", f.Namespace, f.Name, err)
			}
			return r.update(ctx, cur, f, now)
		}
		return fmt.Errorf("creating finding %s/%s: %w", f.Namespace, f.Name, err)
	}
	orig := f.DeepCopy()
	t := metav1.NewTime(now)
	f.Status.State = securityv1alpha1.FindingOpen
	f.Status.FirstDetectedAt, f.Status.LastDetectedAt = &t, &t
	return patchStatus(ctx, r.Client, f, orig)
}

// update brings an existing finding in line with want and keeps it open. lastDetectedAt
// is refreshed at most once per Refresh.
func (r *FindingRecorder) update(ctx context.Context, cur, want *securityv1alpha1.SecurityFinding, now time.Time) error {
	if !ownedFieldsEqual(cur, want) {
		orig := cur.DeepCopy()
		if cur.Labels == nil {
			cur.Labels = map[string]string{}
		}
		maps.Copy(cur.Labels, want.Labels)
		cur.OwnerReferences = want.OwnerReferences
		cur.Spec = want.Spec
		if err := r.Client.Patch(ctx, cur, client.MergeFrom(orig)); err != nil {
			return fmt.Errorf("updating finding %s/%s: %w", cur.Namespace, cur.Name, err)
		}
	}
	orig := cur.DeepCopy()
	t := metav1.NewTime(now)
	st := &cur.Status
	switch {
	case st.State != securityv1alpha1.FindingOpen:
		st.State, st.ResolvedAt, st.LastDetectedAt = securityv1alpha1.FindingOpen, nil, &t
	case st.LastDetectedAt == nil || (r.Refresh > 0 && now.Sub(st.LastDetectedAt.Time) >= r.Refresh):
		st.LastDetectedAt = &t
	}
	if st.FirstDetectedAt == nil {
		st.FirstDetectedAt = &t
	}
	if equality.Semantic.DeepEqual(orig.Status, cur.Status) {
		return nil
	}
	return patchStatus(ctx, r.Client, cur, orig)
}

// ownedFieldsEqual compares the fields the operator writes outside the status.
func ownedFieldsEqual(cur, want *securityv1alpha1.SecurityFinding) bool {
	for k, v := range want.Labels {
		if cur.Labels[k] != v {
			return false
		}
	}
	return equality.Semantic.DeepEqual(cur.OwnerReferences, want.OwnerReferences) &&
		equality.Semantic.DeepEqual(cur.Spec, want.Spec)
}

// resolve marks an open finding Resolved. A finding deleted meanwhile (its owner was
// deleted) needs nothing.
func resolve(ctx context.Context, c client.Client, f *securityv1alpha1.SecurityFinding, now time.Time) error {
	if f.Status.State == securityv1alpha1.FindingResolved && f.Labels[securityv1alpha1.LabelState] == string(securityv1alpha1.FindingResolved) {
		return nil
	}
	if f.Labels[securityv1alpha1.LabelState] != string(securityv1alpha1.FindingResolved) {
		orig := f.DeepCopy()
		if f.Labels == nil {
			f.Labels = map[string]string{}
		}
		f.Labels[securityv1alpha1.LabelState] = string(securityv1alpha1.FindingResolved)
		if err := c.Patch(ctx, f, client.MergeFrom(orig)); err != nil {
			return client.IgnoreNotFound(fmt.Errorf("resolving finding %s/%s: %w", f.Namespace, f.Name, err))
		}
	}
	if f.Status.State == securityv1alpha1.FindingResolved {
		return nil
	}
	orig := f.DeepCopy()
	t := metav1.NewTime(now)
	f.Status.State, f.Status.ResolvedAt = securityv1alpha1.FindingResolved, &t
	return client.IgnoreNotFound(patchStatus(ctx, c, f, orig))
}

func patchStatus(ctx context.Context, c client.Client, f, orig *securityv1alpha1.SecurityFinding) error {
	if err := c.Status().Patch(ctx, f, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("updating status of finding %s/%s: %w", f.Namespace, f.Name, err)
	}
	return nil
}
