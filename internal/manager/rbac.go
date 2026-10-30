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

// The operator's complete permission set, generated into config/rbac/role.yaml by
// "make manifests". Monitored resources are read-only. The only objects it writes are its
// own SecurityFindings, SecurityReports and SecurityPolicy status. It never writes
// workloads, Pods, Secrets or RBAC objects.
//
// A ClusterRole is required because workloads in every selected namespace and the
// cluster-scoped ClusterRoles/ClusterRoleBindings are watched. Secrets are not listed
// here: the Helm chart grants "get" on the notification Secrets by name, in the
// operator's namespace only.

// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets;replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs;cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;serviceaccounts;namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings;clusterroles;clusterrolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.clustersentinel.io,resources=securitypolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.clustersentinel.io,resources=securitypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.clustersentinel.io,resources=securityfindings;securityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.clustersentinel.io,resources=securityfindings/status;securityreports/status,verbs=get;update;patch
