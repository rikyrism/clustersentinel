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

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/rikyrism/clustersentinel/internal/rules"
)

// namespaceReconciler evaluates namespace rules: whether a namespace with Pods has a
// NetworkPolicy. It runs only when that rule is enabled, so NetworkPolicies are not
// watched otherwise.
type namespaceReconciler struct{ *Scanner }

// podCountChanged passes Pod creates and deletes only; updates never change whether a
// namespace has Pods.
var podCountChanged = predicate.Funcs{
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}

func (s *Scanner) setupNamespaces(mgr ctrl.Manager) error {
	toNamespace := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: o.GetNamespace()}}}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("namespace").
		For(&corev1.Namespace{}).
		Watches(&networkingv1.NetworkPolicy{}, toNamespace).
		Watches(&corev1.Pod{}, toNamespace, builder.WithPredicates(podCountChanged)).
		WithOptions(s.options()).
		Complete(&namespaceReconciler{Scanner: s})
}

func (r *namespaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	key := keyFor("Namespace", req.NamespacedName)
	ns := &corev1.Namespace{}
	if err := r.Client.Get(ctx, req.NamespacedName, ns); err != nil {
		if apierrors.IsNotFound(err) {
			return r.gone(ctx, key)
		}
		return ctrl.Result{}, err
	}
	if !ns.DeletionTimestamp.IsZero() {
		return r.gone(ctx, key)
	}
	if !r.Namespaces.NamespaceSelected(ns.Name) {
		return r.forget(ctx, key)
	}
	// Only the counts matter: skip the deep copy of every cached Pod.
	pods := &corev1.PodList{}
	if err := r.Client.List(ctx, pods, client.InNamespace(ns.Name), client.UnsafeDisableDeepCopy); err != nil {
		return ctrl.Result{}, err
	}
	policies := &networkingv1.NetworkPolicyList{}
	if err := r.Client.List(ctx, policies, client.InNamespace(ns.Name), client.UnsafeDisableDeepCopy); err != nil {
		return ctrl.Result{}, err
	}
	vs := rules.EvaluateNamespace(len(pods.Items) > 0, len(policies.Items) > 0, r.Settings)
	if err := r.Recorder.Record(ctx, key, affected("v1", "Namespace", ns), vs); err != nil {
		return ctrl.Result{}, err
	}
	return r.done()
}
