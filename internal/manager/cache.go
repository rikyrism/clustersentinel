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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
//     metadata; Pods controlled by anything else (bare ReplicaSets, custom controllers)
//     keep their spec so they are still analyzed;
//   - when namespaces.include is set, only those namespaces and the operator's own
//     namespace (where it keeps its report and cluster-scoped findings) are cached.
func CacheOptions(cfg config.Config, operatorNamespace string) cache.Options {
	opts := cache.Options{
		DefaultTransform: StripObject,
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {Transform: StripPod},
		},
	}
	if inc := cfg.Scanner.Namespaces.Include; len(inc) > 0 {
		opts.DefaultNamespaces = make(map[string]cache.Config, len(inc))
		for _, ns := range inc {
			opts.DefaultNamespaces[ns] = cache.Config{}
		}
		opts.DefaultNamespaces[operatorNamespace] = cache.Config{}
	}
	return opts
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
	ref := metav1.GetControllerOfNoCopy(pod)
	if ref == nil {
		return false
	}
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil {
		return false
	}
	return templateControllers[schema.GroupKind{Group: gv.Group, Kind: ref.Kind}]
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
