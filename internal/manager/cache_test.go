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

package manager

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rikyrism/clustersentinel/internal/config"
)

func TestStripObjectDropsManagedFieldsAndLastApplied(t *testing.T) {
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
		Annotations:   map[string]string{lastAppliedAnnotation: "{...}", "keep": "me"},
	}}
	out, err := StripObject(d)
	if err != nil {
		t.Fatal(err)
	}
	got := out.(*appsv1.Deployment)
	if got.ManagedFields != nil {
		t.Error("managedFields kept")
	}
	if _, ok := got.Annotations[lastAppliedAnnotation]; ok || got.Annotations["keep"] != "me" {
		t.Errorf("annotations = %v", got.Annotations)
	}
}

func TestStripPod(t *testing.T) {
	isController := true
	spec := corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "c", Image: "nginx"}}}
	owned := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", Controller: &isController}}},
		Spec:   spec,
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	standalone := &corev1.Pod{Spec: spec, Status: corev1.PodStatus{Phase: corev1.PodRunning, Message: "x"}}

	o, _ := StripPod(owned)
	if p := o.(*corev1.Pod); len(p.Spec.Containers) != 0 || p.Status.Phase != "" {
		t.Error("an owned pod must keep metadata only")
	}
	for _, ref := range []metav1.OwnerReference{
		{APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout", Name: "r", Controller: &isController},
		{APIVersion: "v1", Kind: "Node", Name: "node-1", Controller: &isController}, // static (mirror) pod
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs"},                     // owner, not controller
	} {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{ref}}, Spec: spec}
		out, _ := StripPod(p)
		if len(out.(*corev1.Pod).Spec.Containers) != 1 {
			t.Errorf("pod owned by %s/%s must keep its spec to be analyzed", ref.APIVersion, ref.Kind)
		}
	}

	s, _ := StripPod(standalone)
	if p := s.(*corev1.Pod); !p.Spec.HostNetwork || len(p.Spec.Containers) != 1 || p.Status.Phase != corev1.PodRunning || p.Status.Message != "" {
		t.Errorf("a standalone pod must keep its spec and phase, got %+v", p)
	}
}

func TestCacheOptionsNamespaces(t *testing.T) {
	cfg := config.Default()
	if opts := CacheOptions(cfg, "clustersentinel-system"); opts.DefaultNamespaces != nil {
		t.Error("an empty include list must cache all namespaces")
	}
	cfg.Scanner.Namespaces.Include = []string{"app", "web"}
	opts := CacheOptions(cfg, "clustersentinel-system")
	_, web := opts.DefaultNamespaces["web"]
	_, own := opts.DefaultNamespaces["clustersentinel-system"]
	if !web || !own || len(opts.DefaultNamespaces) != 3 {
		t.Errorf("DefaultNamespaces = %v", opts.DefaultNamespaces)
	}
}
