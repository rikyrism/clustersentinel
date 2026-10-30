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

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/rikyrism/clustersentinel/internal/manager"
	"github.com/rikyrism/clustersentinel/internal/rules"
)

// workloadKind describes a workload type whose pod template is analyzed.
type workloadKind struct {
	apiVersion string
	kind       string
	newObject  func() client.Object
	newList    func() client.ObjectList
	// podSpec returns the pod spec to analyze and its path in the object, or nil when the
	// object is covered by another analysis (a Deployment's ReplicaSet, a CronJob's Job).
	podSpec func(client.Object) (*corev1.PodSpec, string)
}

const templateSpecPath = "spec.template.spec"

var workloadKinds = []workloadKind{
	{
		apiVersion: appsv1.SchemeGroupVersion.String(), kind: "Deployment",
		newObject: func() client.Object { return &appsv1.Deployment{} },
		newList:   func() client.ObjectList { return &appsv1.DeploymentList{} },
		podSpec: func(o client.Object) (*corev1.PodSpec, string) {
			return &o.(*appsv1.Deployment).Spec.Template.Spec, templateSpecPath
		},
	},
	{
		apiVersion: appsv1.SchemeGroupVersion.String(), kind: "StatefulSet",
		newObject: func() client.Object { return &appsv1.StatefulSet{} },
		newList:   func() client.ObjectList { return &appsv1.StatefulSetList{} },
		podSpec: func(o client.Object) (*corev1.PodSpec, string) {
			return &o.(*appsv1.StatefulSet).Spec.Template.Spec, templateSpecPath
		},
	},
	{
		apiVersion: appsv1.SchemeGroupVersion.String(), kind: "DaemonSet",
		newObject: func() client.Object { return &appsv1.DaemonSet{} },
		newList:   func() client.ObjectList { return &appsv1.DaemonSetList{} },
		podSpec: func(o client.Object) (*corev1.PodSpec, string) {
			return &o.(*appsv1.DaemonSet).Spec.Template.Spec, templateSpecPath
		},
	},
	{
		// ReplicaSets of other controllers (Argo Rollouts, for example) are analyzed while
		// they run; scaled-down old revisions are not, so each revision is not reported again.
		apiVersion: appsv1.SchemeGroupVersion.String(), kind: "ReplicaSet",
		newObject: func() client.Object { return &appsv1.ReplicaSet{} },
		newList:   func() client.ObjectList { return &appsv1.ReplicaSetList{} },
		podSpec: func(o client.Object) (*corev1.PodSpec, string) {
			rs := o.(*appsv1.ReplicaSet)
			if manager.IsDeploymentControlled(rs) || (rs.Spec.Replicas != nil && *rs.Spec.Replicas == 0) {
				return nil, ""
			}
			return &rs.Spec.Template.Spec, templateSpecPath
		},
	},
	{
		apiVersion: batchv1.SchemeGroupVersion.String(), kind: "Job",
		newObject: func() client.Object { return &batchv1.Job{} },
		newList:   func() client.ObjectList { return &batchv1.JobList{} },
		podSpec: func(o client.Object) (*corev1.PodSpec, string) {
			job := o.(*batchv1.Job)
			if manager.IsCronJobControlled(job) {
				return nil, ""
			}
			return &job.Spec.Template.Spec, templateSpecPath
		},
	},
	{
		apiVersion: batchv1.SchemeGroupVersion.String(), kind: "CronJob",
		newObject: func() client.Object { return &batchv1.CronJob{} },
		newList:   func() client.ObjectList { return &batchv1.CronJobList{} },
		podSpec: func(o client.Object) (*corev1.PodSpec, string) {
			return &o.(*batchv1.CronJob).Spec.JobTemplate.Spec.Template.Spec, "spec.jobTemplate.spec.template.spec"
		},
	},
}

type workloadReconciler struct {
	*Scanner
	workloadKind
}

func (s *Scanner) setupWorkload(ctx context.Context, mgr ctrl.Manager, k workloadKind) error {
	b := ctrl.NewControllerManagedBy(mgr).
		Named(strings.ToLower(k.kind)).
		For(k.newObject(), builder.WithPredicates(specChanged)).
		WithOptions(s.options())
	if s.Settings.Enabled(rules.IDServiceAccountToken) {
		if err := mgr.GetFieldIndexer().IndexField(ctx, k.newObject(), indexServiceAccount, func(o client.Object) []string {
			if spec, _ := k.podSpec(o); spec != nil {
				return []string{rules.ServiceAccountName(spec)}
			}
			return nil
		}); err != nil {
			return err
		}
		b = b.Watches(&corev1.ServiceAccount{},
			handler.EnqueueRequestsFromMapFunc(s.byServiceAccount(k.newList, requestFor)),
			builder.WithPredicates(automountChanged))
	}
	return b.Complete(&workloadReconciler{Scanner: s, workloadKind: k})
}

func (r *workloadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	key := keyFor(r.kind, req.NamespacedName)
	obj := r.newObject()
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return r.forget(ctx, key)
		}
		return ctrl.Result{}, err
	}
	spec, path := r.podSpec(obj)
	if spec == nil || !obj.GetDeletionTimestamp().IsZero() || !r.Namespaces.NamespaceSelected(req.Namespace) {
		return r.forget(ctx, key)
	}
	sa, err := r.serviceAccount(ctx, req.Namespace, spec)
	if err != nil {
		return ctrl.Result{}, err
	}
	vs := rules.EvaluateWorkload(rules.Workload{SpecPath: path, Spec: spec, ServiceAccount: sa}, r.Settings)
	r.Recorder.Record(ctx, key, affected(r.apiVersion, r.kind, obj), vs)
	return r.done()
}
