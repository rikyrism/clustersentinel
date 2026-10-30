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

package rules

// Guidance is the human-readable text of a rule, copied into its findings.
type Guidance struct {
	// Description says why the setting matters.
	Description string
	// Recommendation says what to change.
	Recommendation string
}

// GuidanceFor returns the description and recommendation of a rule.
func GuidanceFor(id string) Guidance { return guidance[id] }

var guidance = map[string]Guidance{
	IDPrivileged: {
		"A privileged container has every capability and access to the host's devices. Escaping to the node is trivial.",
		"Remove securityContext.privileged, or set it to false. Grant only the specific capabilities the container needs.",
	},
	IDPrivilegeEscalation: {
		"Without allowPrivilegeEscalation: false, a process can gain more privileges than its parent, for example through setuid binaries.",
		"Set securityContext.allowPrivilegeEscalation: false on every container.",
	},
	IDRunAsRoot: {
		"A container running as UID 0 is root inside the container, and much closer to root on the node if it escapes.",
		"Set securityContext.runAsNonRoot: true and a non-zero runAsUser, on the pod or on each container, and use an image that runs as a non-root user.",
	},
	IDReadOnlyRootFilesystem: {
		"A writable root filesystem lets an attacker modify binaries and drop tools inside the container.",
		"Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir for paths the application must write to, such as /tmp.",
	},
	IDDropCapabilities: {
		"Containers start with a default set of Linux capabilities that most applications never use.",
		"Set securityContext.capabilities.drop: [\"ALL\"] and add back only what the container needs, such as NET_BIND_SERVICE.",
	},
	IDDangerousCapabilities: {
		"Capabilities such as SYS_ADMIN, NET_ADMIN or SYS_PTRACE give control over the host kernel, the network or other processes.",
		"Remove these capabilities from securityContext.capabilities.add. If one is truly needed, isolate the workload on dedicated nodes.",
	},
	IDSeccompProfile: {
		"Without a seccomp profile, a container can make any system call, which widens the kernel attack surface.",
		"Set securityContext.seccompProfile.type: RuntimeDefault on the pod.",
	},
	IDHostNetwork: {
		"A pod on the host network sees every interface of the node and can reach services bound to localhost on it.",
		"Remove hostNetwork: true. Expose the pod through a Service instead.",
	},
	IDHostPID: {
		"A pod in the host PID namespace can see, and possibly signal or trace, every process on the node.",
		"Remove hostPID: true.",
	},
	IDHostIPC: {
		"A pod in the host IPC namespace can read and write the shared memory of every process on the node.",
		"Remove hostIPC: true.",
	},
	IDLatestImageTag: {
		"The latest tag changes over time, so the same manifest can run different code after a restart, and rollbacks are unreliable.",
		"Use an explicit version tag, or better, pin the image by digest (image@sha256:...).",
	},
	IDImplicitImageTag: {
		"An image without a tag pulls latest, with the same problems as an explicit latest tag.",
		"Add an explicit version tag, or pin the image by digest (image@sha256:...).",
	},
	IDServiceAccountToken: {
		"An automounted API token lets anyone who compromises the container talk to the Kubernetes API with the ServiceAccount's permissions.",
		"Set automountServiceAccountToken: false on the pod or the ServiceAccount, unless the application calls the Kubernetes API.",
	},
	IDDefaultServiceAccount: {
		"Workloads sharing the default ServiceAccount share its permissions, and any permission granted to it reaches all of them.",
		"Create a dedicated ServiceAccount for the workload and set spec.serviceAccountName.",
	},
	IDWildcardRBAC: {
		"A wildcard verb or resource grants every current and future permission in scope, including ones added by new API versions and CRDs.",
		"List the exact verbs and resources the subject needs instead of \"*\".",
	},
	IDClusterAdminBinding: {
		"cluster-admin can do anything in the cluster. A compromised subject bound to it compromises the whole cluster.",
		"Bind a narrower ClusterRole or a namespaced Role that grants only what the subject needs.",
	},
	IDBroadRBAC: {
		"Reading Secrets, executing into Pods, proxying to nodes, minting tokens, impersonating or escalating can each lead to more access than the role appears to grant.",
		"Remove the permission, or restrict it with resourceNames to the specific objects needed.",
	},
	IDMissingNetworkPolicy: {
		"Without a NetworkPolicy, every Pod in the namespace accepts traffic from every Pod in the cluster.",
		"Add a default-deny NetworkPolicy to the namespace and allow the traffic each workload needs. This only has an effect if the CNI plugin enforces NetworkPolicy.",
	},
}
