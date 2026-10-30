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

// Package manager builds the controller-runtime manager options for ClusterSentinel.
package manager

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rikyrism/clustersentinel/internal/config"
)

const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// CacheOptions keeps the informer cache small:
//   - managedFields and the last-applied annotation are dropped from every cached object;
//   - Pods controlled by a workload whose template ClusterSentinel analyzes keep only
//     metadata; Pods controlled by anything else (custom controllers) keep their spec so
//     they are still analyzed;
//   - ReplicaSets owned by a Deployment and Jobs owned by a CronJob drop their pod
//     template, because the Deployment or CronJob template is analyzed instead;
//   - namespaces.exclude is sent to the API server as a field selector, so objects in
//     excluded namespaces are never transferred or cached;
//   - when namespaces.include is set, only those namespaces and the operator's own
//     namespace (where it keeps its report and cluster-scoped findings) are cached.
func CacheOptions(cfg config.Config, operatorNamespace string) cache.Options {
	byObject := map[client.Object]cache.ByObject{}
	exclude := excludeSelector(cfg.Scanner.Namespaces.Exclude)
	for _, obj := range namespacedWatched() {
		byObject[obj] = cache.ByObject{Field: exclude, Transform: transformFor(obj)}
	}
	opts := cache.Options{DefaultTransform: StripObject, ByObject: byObject}
	if inc := cfg.Scanner.Namespaces.Include; len(inc) > 0 {
		opts.DefaultNamespaces = make(map[string]cache.Config, len(inc))
		for _, ns := range inc {
			opts.DefaultNamespaces[ns] = cache.Config{}
		}
		opts.DefaultNamespaces[operatorNamespace] = cache.Config{}
	}
	return opts
}

// namespacedWatched lists the namespaced types the controllers watch.
func namespacedWatched() []client.Object {
	return []client.Object{
		&corev1.Pod{}, &corev1.ServiceAccount{},
		&appsv1.Deployment{}, &appsv1.StatefulSet{}, &appsv1.DaemonSet{}, &appsv1.ReplicaSet{},
		&batchv1.Job{}, &batchv1.CronJob{},
		&rbacv1.Role{}, &rbacv1.RoleBinding{}, &networkingv1.NetworkPolicy{},
	}
}

func transformFor(obj client.Object) toolscache.TransformFunc {
	switch obj.(type) {
	case *corev1.Pod:
		return StripPod
	case *appsv1.ReplicaSet:
		return StripReplicaSet
	case *batchv1.Job:
		return StripJob
	default:
		return StripObject
	}
}

// excludeSelector matches objects outside the excluded namespaces, or nil when nothing is
// excluded. metadata.namespace is a field selector every namespaced resource supports.
func excludeSelector(exclude []string) fields.Selector {
	if len(exclude) == 0 {
		return nil
	}
	sels := make([]fields.Selector, 0, len(exclude))
	for _, ns := range exclude {
		sels = append(sels, fields.OneTermNotEqualSelector("metadata.namespace", ns))
	}
	return fields.AndSelectors(sels...)
}

// UncachedObjects are always read directly from the API server and never cached, so the
// operator never holds Secret or ConfigMap contents in memory beyond a single read.
func UncachedObjects() []client.Object {
	return []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}}
}

// StripObject removes fields ClusterSentinel never reads. It is safe on any object.
func StripObject(obj any) (any, error) {
	if tomb, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		return tomb, nil
	}
	if m, ok := obj.(metav1.Object); ok {
		m.SetManagedFields(nil)
		if a := m.GetAnnotations(); a != nil {
			if _, ok := a[lastAppliedAnnotation]; ok {
				delete(a, lastAppliedAnnotation)
				m.SetAnnotations(a)
			}
		}
	}
	return obj, nil
}

// controlledBy reports whether obj's controller has the given group and kind.
func controlledBy(obj metav1.Object, gk schema.GroupKind) bool {
	ref := metav1.GetControllerOfNoCopy(obj)
	if ref == nil {
		return false
	}
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	return err == nil && gv.Group == gk.Group && ref.Kind == gk.Kind
}

var (
	deploymentKind = appsv1.SchemeGroupVersion.WithKind("Deployment").GroupKind()
	cronJobKind    = batchv1.SchemeGroupVersion.WithKind("CronJob").GroupKind()
)

// IsDeploymentControlled reports whether a ReplicaSet belongs to a Deployment.
func IsDeploymentControlled(rs metav1.Object) bool { return controlledBy(rs, deploymentKind) }

// IsCronJobControlled reports whether a Job belongs to a CronJob.
func IsCronJobControlled(job metav1.Object) bool { return controlledBy(job, cronJobKind) }

// StripReplicaSet applies StripObject and drops the pod template and status of
// ReplicaSets that belong to a Deployment. Old revisions are kept by Deployments, so this
// is most of the ReplicaSet cache.
func StripReplicaSet(obj any) (any, error) {
	obj, _ = StripObject(obj)
	if rs, ok := obj.(*appsv1.ReplicaSet); ok {
		rs.Status = appsv1.ReplicaSetStatus{}
		if IsDeploymentControlled(rs) {
			rs.Spec.Template = corev1.PodTemplateSpec{}
		}
	}
	return obj, nil
}

// StripJob applies StripObject and drops the pod template and status of Jobs that belong
// to a CronJob.
func StripJob(obj any) (any, error) {
	obj, _ = StripObject(obj)
	if job, ok := obj.(*batchv1.Job); ok {
		job.Status = batchv1.JobStatus{}
		if IsCronJobControlled(job) {
			job.Spec.Template = corev1.PodTemplateSpec{}
		}
	}
	return obj, nil
}

// templateControllers are the Pod controllers whose pod template is analyzed instead of
// the individual Pods (ReplicaSets are covered through their Deployment).
var templateControllers = map[schema.GroupKind]bool{
	appsv1.SchemeGroupVersion.WithKind("ReplicaSet").GroupKind():  true,
	appsv1.SchemeGroupVersion.WithKind("StatefulSet").GroupKind(): true,
	appsv1.SchemeGroupVersion.WithKind("DaemonSet").GroupKind():   true,
	batchv1.SchemeGroupVersion.WithKind("Job").GroupKind():        true,
}

// IsTemplateControlled reports whether a Pod's controller is analyzed at the template level.
func IsTemplateControlled(pod metav1.Object) bool {
	for gk := range templateControllers {
		if controlledBy(pod, gk) {
			return true
		}
	}
	return false
}

// StripPod applies StripObject and, for template-controlled Pods, drops spec and status.
func StripPod(obj any) (any, error) {
	obj, _ = StripObject(obj)
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	if IsTemplateControlled(pod) {
		pod.Spec = corev1.PodSpec{}
		pod.Status = corev1.PodStatus{}
	} else {
		pod.Status = corev1.PodStatus{Phase: pod.Status.Phase}
	}
	return pod, nil
}
