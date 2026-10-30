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

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rikyrism/clustersentinel/internal/rules"
)

const rbacAPIVersion = "rbac.authorization.k8s.io/v1"

// RBAC objects have no spec generation, so their controllers see every update. They change
// rarely, and aggregated ClusterRoles, which the API server rewrites, are dropped after a
// cache read.

type roleKind struct {
	kind      string
	newObject func() client.Object
	// policy returns the rules to evaluate, or false when the role is not evaluated.
	policy func(client.Object) ([]rbacv1.PolicyRule, bool)
}

var roleKinds = []roleKind{
	{
		kind:      "Role",
		newObject: func() client.Object { return &rbacv1.Role{} },
		policy:    func(o client.Object) ([]rbacv1.PolicyRule, bool) { return o.(*rbacv1.Role).Rules, true },
	},
	{
		// An aggregated ClusterRole only collects the rules of other ClusterRoles, which are
		// evaluated themselves.
		kind:      "ClusterRole",
		newObject: func() client.Object { return &rbacv1.ClusterRole{} },
		policy: func(o client.Object) ([]rbacv1.PolicyRule, bool) {
			cr := o.(*rbacv1.ClusterRole)
			return cr.Rules, cr.AggregationRule == nil
		},
	},
}

type roleReconciler struct {
	*Scanner
	roleKind
}

func (s *Scanner) setupRole(mgr ctrl.Manager, k roleKind) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(strings.ToLower(k.kind)).
		For(k.newObject()).
		WithOptions(s.options()).
		Complete(&roleReconciler{Scanner: s, roleKind: k})
}

func (r *roleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	key := keyFor(r.kind, req.NamespacedName)
	obj := r.newObject()
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return r.forget(ctx, key)
		}
		return ctrl.Result{}, err
	}
	policy, ok := r.policy(obj)
	if !ok || rules.IsBuiltInRBAC(obj) || !r.inScope(obj) {
		return r.forget(ctx, key)
	}
	r.Recorder.Record(ctx, key, affected(rbacAPIVersion, r.kind, obj), rules.EvaluateRole(policy, r.Settings))
	return r.done()
}

type bindingKind struct {
	kind      string
	newObject func() client.Object
	binding   func(client.Object) (rbacv1.RoleRef, []rbacv1.Subject)
}

var bindingKinds = []bindingKind{
	{
		kind:      "RoleBinding",
		newObject: func() client.Object { return &rbacv1.RoleBinding{} },
		binding: func(o client.Object) (rbacv1.RoleRef, []rbacv1.Subject) {
			b := o.(*rbacv1.RoleBinding)
			return b.RoleRef, b.Subjects
		},
	},
	{
		kind:      "ClusterRoleBinding",
		newObject: func() client.Object { return &rbacv1.ClusterRoleBinding{} },
		binding: func(o client.Object) (rbacv1.RoleRef, []rbacv1.Subject) {
			b := o.(*rbacv1.ClusterRoleBinding)
			return b.RoleRef, b.Subjects
		},
	},
}

type bindingReconciler struct {
	*Scanner
	bindingKind
}

func (s *Scanner) setupBinding(mgr ctrl.Manager, k bindingKind) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(strings.ToLower(k.kind)).
		For(k.newObject()).
		WithOptions(s.options()).
		Complete(&bindingReconciler{Scanner: s, bindingKind: k})
}

func (r *bindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	key := keyFor(r.kind, req.NamespacedName)
	obj := r.newObject()
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return r.forget(ctx, key)
		}
		return ctrl.Result{}, err
	}
	if rules.IsBuiltInRBAC(obj) || !r.inScope(obj) {
		return r.forget(ctx, key)
	}
	roleRef, subjects := r.binding(obj)
	r.Recorder.Record(ctx, key, affected(rbacAPIVersion, r.kind, obj), rules.EvaluateBinding(roleRef, subjects, r.Settings))
	return r.done()
}

// inScope reports whether obj is cluster-scoped or in a selected namespace.
func (s *Scanner) inScope(obj client.Object) bool {
	return obj.GetNamespace() == "" || s.Namespaces.NamespaceSelected(obj.GetNamespace())
}
