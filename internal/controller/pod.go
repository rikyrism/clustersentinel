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
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/rikyrism/clustersentinel/internal/manager"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// Pods are analyzed only when no workload template covers them:
//   - standalone Pods and static (mirror) Pods are analyzed one by one;
//   - Pods of controllers ClusterSentinel does not know (operators, custom resources) are
//     analyzed as one group per controller, reported against the controller, so 50
//     replicas give one result and not 50.
//
// A group's request name is groupPrefix + the controller UID. Pod names cannot contain
// ":", so the two kinds of request never collide.
const (
	groupPrefix        = "controller:"
	indexPodController = "clustersentinel.controllerUID"
	podSpecPath        = "spec"
)

// podGroupController returns the controller a Pod is grouped by, or nil when the Pod is
// analyzed on its own.
func podGroupController(pod *corev1.Pod) *metav1.OwnerReference {
	ref := metav1.GetControllerOfNoCopy(pod)
	if ref == nil || (ref.APIVersion == "v1" && ref.Kind == "Node") {
		return nil
	}
	return ref
}

// podRequest maps a Pod to the request that analyzes it. Pods covered by a workload
// template are dropped.
func podRequest(obj client.Object) (reconcile.Request, bool) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || manager.IsTemplateControlled(pod) {
		return reconcile.Request{}, false
	}
	name := pod.Name
	if ref := podGroupController(pod); ref != nil {
		name = groupPrefix + string(ref.UID)
	}
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: pod.Namespace, Name: name}}, true
}

type podReconciler struct{ *Scanner }

func (s *Scanner) setupPods(ctx context.Context, mgr ctrl.Manager) error {
	indexer := mgr.GetFieldIndexer()
	if err := indexer.IndexField(ctx, &corev1.Pod{}, indexPodController, func(o client.Object) []string {
		if pod := o.(*corev1.Pod); !manager.IsTemplateControlled(pod) {
			if ref := podGroupController(pod); ref != nil {
				return []string{string(ref.UID)}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	toRequests := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		if req, ok := podRequest(o); ok {
			return []reconcile.Request{req}
		}
		return nil
	})
	b := ctrl.NewControllerManagedBy(mgr).
		Named("pod").
		Watches(&corev1.Pod{}, toRequests, builder.WithPredicates(specChanged)).
		WithOptions(s.options())
	if s.Settings.Enabled(rules.IDServiceAccountToken) {
		// Template-controlled Pods have no spec in the cache, so they are not indexed.
		if err := indexer.IndexField(ctx, &corev1.Pod{}, indexServiceAccount, func(o client.Object) []string {
			if pod := o.(*corev1.Pod); !manager.IsTemplateControlled(pod) {
				return []string{rules.ServiceAccountName(&pod.Spec)}
			}
			return nil
		}); err != nil {
			return err
		}
		b = b.Watches(&corev1.ServiceAccount{},
			handler.EnqueueRequestsFromMapFunc(s.byServiceAccount(func() client.ObjectList { return &corev1.PodList{} }, podRequest)),
			builder.WithPredicates(automountChanged))
	}
	return b.Complete(&podReconciler{Scanner: s})
}

func (r *podReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	key := keyFor("Pod", req.NamespacedName)
	if !r.Namespaces.NamespaceSelected(req.Namespace) {
		return r.forget(ctx, key)
	}
	if uid, ok := strings.CutPrefix(req.Name, groupPrefix); ok {
		return r.reconcileGroup(ctx, key, req.Namespace, uid)
	}
	pod := &corev1.Pod{}
	if err := r.Client.Get(ctx, req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return r.forget(ctx, key)
		}
		return ctrl.Result{}, err
	}
	// A Pod adopted by a controller since it was enqueued is analyzed elsewhere now.
	if want, ok := podRequest(pod); !ok || want != req || !pod.DeletionTimestamp.IsZero() {
		return r.forget(ctx, key)
	}
	vs, err := r.evaluatePod(ctx, pod)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Record(ctx, key, affected("v1", "Pod", pod), vs)
	return r.done()
}

// reconcileGroup analyzes every Pod of one controller and reports the union of their
// violations against the controller.
func (r *podReconciler) reconcileGroup(ctx context.Context, key, namespace, uid string) (ctrl.Result, error) {
	list := &corev1.PodList{}
	if err := r.Client.List(ctx, list, client.InNamespace(namespace), client.MatchingFields{indexPodController: uid}); err != nil {
		return ctrl.Result{}, err
	}
	pods := slices.DeleteFunc(list.Items, func(p corev1.Pod) bool { return !p.DeletionTimestamp.IsZero() })
	if len(pods) == 0 {
		return r.forget(ctx, key)
	}
	// Cache lists are unordered; sort so the reported evidence is stable.
	slices.SortFunc(pods, func(a, b corev1.Pod) int { return cmp.Compare(a.Name, b.Name) })

	type ruleContainer struct{ rule, container string }
	seen := map[ruleContainer]bool{}
	var merged []rules.Violation
	for i := range pods {
		vs, err := r.evaluatePod(ctx, &pods[i])
		if err != nil {
			return ctrl.Result{}, err
		}
		for _, v := range vs {
			if k := (ruleContainer{v.RuleID, v.Container}); !seen[k] {
				seen[k] = true
				merged = append(merged, v)
			}
		}
	}
	// Keep catalog order, as for a single Pod.
	order := map[string]int{}
	for i, m := range rules.Catalog {
		order[m.ID] = i
	}
	slices.SortStableFunc(merged, func(a, b rules.Violation) int { return cmp.Compare(order[a.RuleID], order[b.RuleID]) })

	ref := podGroupController(&pods[0])
	res := affected(ref.APIVersion, ref.Kind, &pods[0])
	res.Name, res.UID = ref.Name, string(ref.UID)
	r.Recorder.Record(ctx, key, res, merged)
	return r.done()
}

func (r *podReconciler) evaluatePod(ctx context.Context, pod *corev1.Pod) ([]rules.Violation, error) {
	sa, err := r.serviceAccount(ctx, pod.Namespace, &pod.Spec)
	if err != nil {
		return nil, err
	}
	return rules.EvaluateWorkload(rules.Workload{SpecPath: podSpecPath, Spec: &pod.Spec, ServiceAccount: sa}, r.Settings), nil
}
