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

// Package controller holds the controllers that watch workloads, Pods, RBAC objects and
// namespaces, run the rules against them and hand the results to a Recorder.
package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/config"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// indexServiceAccount indexes objects with a pod spec by the ServiceAccount it runs as, so
// a ServiceAccount change re-analyzes only the workloads that use it.
const indexServiceAccount = "clustersentinel.serviceAccountName"

// Scanner holds what every controller shares.
type Scanner struct {
	Client   client.Client
	Recorder Recorder
	// Namespaces selects the namespaces whose objects are analyzed.
	Namespaces config.Namespaces
	// Settings is the effective rule set. SecurityPolicy support (Phase 4) makes it
	// per namespace.
	Settings rules.Settings
	// Rescan re-analyzes every object this often, from the cache. Zero disables it.
	Rescan                  time.Duration
	MaxConcurrentReconciles int
}

// Setup registers the controllers that the enabled rules need. Controllers (and so
// informers) for disabled rule scopes are not started, which keeps their objects out of
// memory entirely.
func Setup(ctx context.Context, mgr ctrl.Manager, s *Scanner) error {
	if s.Settings.AnyEnabled(rules.IDsInScope(rules.ScopeWorkload)...) {
		for _, k := range workloadKinds {
			if err := s.setupWorkload(ctx, mgr, k); err != nil {
				return err
			}
		}
		if err := s.setupPods(ctx, mgr); err != nil {
			return err
		}
	}
	if s.Settings.AnyEnabled(rules.IDWildcardRBAC, rules.IDBroadRBAC) {
		for _, k := range roleKinds {
			if err := s.setupRole(mgr, k); err != nil {
				return err
			}
		}
	}
	if s.Settings.Enabled(rules.IDClusterAdminBinding) {
		for _, k := range bindingKinds {
			if err := s.setupBinding(mgr, k); err != nil {
				return err
			}
		}
	}
	if s.Settings.Enabled(rules.IDMissingNetworkPolicy) {
		if err := s.setupNamespaces(mgr); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) options() controller.Options {
	return controller.Options{MaxConcurrentReconciles: s.MaxConcurrentReconciles}
}

// done ends a successful reconcile, scheduling the periodic rescan with 10% jitter so
// rescans spread out instead of arriving all at once.
func (s *Scanner) done() (ctrl.Result, error) {
	if s.Rescan <= 0 {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: wait.Jitter(s.Rescan, 0.1)}, nil
}

// forget drops key and ends the reconcile without a rescan: there is nothing left to scan.
func (s *Scanner) forget(ctx context.Context, key string) (ctrl.Result, error) {
	s.Recorder.Forget(ctx, key)
	return ctrl.Result{}, nil
}

// serviceAccount returns a ServiceAccount, or nil when it does not exist. It is only read
// when the serviceAccountToken rule needs it.
func (s *Scanner) serviceAccount(ctx context.Context, namespace string, spec *corev1.PodSpec) (*corev1.ServiceAccount, error) {
	if !s.Settings.Enabled(rules.IDServiceAccountToken) {
		return nil, nil
	}
	sa := &corev1.ServiceAccount{}
	err := s.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: rules.ServiceAccountName(spec)}, sa)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sa, nil
}

// keyFor returns the Recorder key of an analyzed unit: "Kind/namespace/name", or
// "Kind/name" for cluster-scoped objects.
func keyFor(kind string, nn types.NamespacedName) string {
	if nn.Namespace == "" {
		return kind + "/" + nn.Name
	}
	return kind + "/" + nn.Namespace + "/" + nn.Name
}

// affected describes obj for a result. Typed objects read from the cache have no TypeMeta,
// so the API version and kind come from the caller.
func affected(apiVersion, kind string, obj metav1.Object) securityv1alpha1.AffectedResource {
	return securityv1alpha1.AffectedResource{
		APIVersion: apiVersion, Kind: kind, Name: obj.GetName(), Namespace: obj.GetNamespace(), UID: string(obj.GetUID()),
	}
}

// specChanged passes creates, deletes and updates that change metadata.generation (the
// spec) or the controller reference. Status-only updates, which are most updates, are
// dropped before they reach the work queue.
var specChanged = predicate.Or(predicate.GenerationChangedPredicate{}, predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return false },
	DeleteFunc:  func(event.DeleteEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
	UpdateFunc: func(e event.UpdateEvent) bool {
		return controllerUID(e.ObjectOld) != controllerUID(e.ObjectNew)
	},
})

func controllerUID(obj metav1.Object) types.UID {
	if ref := metav1.GetControllerOfNoCopy(obj); ref != nil {
		return ref.UID
	}
	return ""
}

// automountChanged passes ServiceAccount events that can change the serviceAccountToken
// result.
var automountChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldSA, okOld := e.ObjectOld.(*corev1.ServiceAccount)
		newSA, okNew := e.ObjectNew.(*corev1.ServiceAccount)
		if !okOld || !okNew {
			return true
		}
		o, n := oldSA.AutomountServiceAccountToken, newSA.AutomountServiceAccountToken
		return (o == nil) != (n == nil) || (o != nil && *o != *n)
	},
}

// byServiceAccount maps a ServiceAccount to the requests of the objects that run as it,
// using indexServiceAccount. toRequest may drop an object or map several to one request.
func (s *Scanner) byServiceAccount(newList func() client.ObjectList,
	toRequest func(client.Object) (reconcile.Request, bool)) handler.MapFunc {
	return func(ctx context.Context, sa client.Object) []reconcile.Request {
		list := newList()
		if err := s.Client.List(ctx, list, client.InNamespace(sa.GetNamespace()),
			client.MatchingFields{indexServiceAccount: sa.GetName()}); err != nil {
			log.FromContext(ctx).Error(err, "Listing objects by ServiceAccount", "serviceAccount", sa.GetName())
			return nil
		}
		seen := map[reconcile.Request]bool{}
		var reqs []reconcile.Request
		_ = meta.EachListItem(list, func(o runtime.Object) error {
			if req, ok := toRequest(o.(client.Object)); ok && !seen[req] {
				seen[req] = true
				reqs = append(reqs, req)
			}
			return nil
		})
		return reqs
	}
}

func requestFor(obj client.Object) (reconcile.Request, bool) {
	return reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)}, true
}
