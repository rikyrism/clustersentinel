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

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

// Violation is one rule failing on one resource, and on one container for container rules.
type Violation struct {
	RuleID   string
	Severity securityv1alpha1.Severity
	// Container is empty for pod-level and non-workload rules.
	Container string
	// Evidence names the offending field and its value, e.g.
	// "spec.template.spec.containers[0].securityContext.privileged is true".
	Evidence string
}

// Workload is a pod spec to analyze, with what the rules need to know about its context.
type Workload struct {
	// SpecPath locates Spec inside the object, e.g. "spec.template.spec" for a Deployment.
	SpecPath string
	Spec     *corev1.PodSpec
	// ServiceAccount is the ServiceAccount the pods run as, or nil when it does not exist
	// (yet) or was not looked up.
	ServiceAccount *corev1.ServiceAccount
}

// ServiceAccountName returns the ServiceAccount a pod spec runs as.
func ServiceAccountName(spec *corev1.PodSpec) string {
	switch {
	case spec.ServiceAccountName != "":
		return spec.ServiceAccountName
	case spec.DeprecatedServiceAccount != "":
		return spec.DeprecatedServiceAccount
	default:
		return "default"
	}
}

// container is the part of a regular, init or ephemeral container the rules read.
type container struct {
	path  string
	name  string
	image string
	sc    *corev1.SecurityContext
}

type podView struct {
	Workload
	containers []container
	// linux is false for Windows pods, where Linux-only settings do not apply.
	linux bool
}

func newPodView(w Workload) *podView {
	p := &podView{Workload: w, linux: w.Spec.OS == nil || w.Spec.OS.Name != corev1.Windows}
	add := func(field string, i int, c *corev1.Container) {
		p.containers = append(p.containers, container{
			path: fmt.Sprintf("%s.%s[%d]", w.SpecPath, field, i), name: c.Name, image: c.Image, sc: c.SecurityContext,
		})
	}
	for i := range w.Spec.InitContainers {
		add("initContainers", i, &w.Spec.InitContainers[i])
	}
	for i := range w.Spec.Containers {
		add("containers", i, &w.Spec.Containers[i])
	}
	for i := range w.Spec.EphemeralContainers {
		c := corev1.Container(w.Spec.EphemeralContainers[i].EphemeralContainerCommon)
		add("ephemeralContainers", i, &c)
	}
	return p
}

// hit is a violation before the rule ID and severity are attached.
type hit struct {
	container string
	evidence  string
}

type workloadCheck func(p *podView) []hit

var workloadChecks = map[string]workloadCheck{
	IDPrivileged:             checkPrivileged,
	IDPrivilegeEscalation:    checkPrivilegeEscalation,
	IDRunAsRoot:              checkRunAsRoot,
	IDReadOnlyRootFilesystem: checkReadOnlyRootFilesystem,
	IDDropCapabilities:       checkDropCapabilities,
	IDDangerousCapabilities:  checkDangerousCapabilities,
	IDSeccompProfile:         checkSeccompProfile,
	IDHostNetwork:            podFlag("hostNetwork", func(s *corev1.PodSpec) bool { return s.HostNetwork }),
	IDHostPID:                podFlag("hostPID", func(s *corev1.PodSpec) bool { return s.HostPID }),
	IDHostIPC:                podFlag("hostIPC", func(s *corev1.PodSpec) bool { return s.HostIPC }),
	IDLatestImageTag:         checkLatestTag,
	IDImplicitImageTag:       checkImplicitTag,
	IDServiceAccountToken:    checkServiceAccountToken,
	IDDefaultServiceAccount:  checkDefaultServiceAccount,
}

// EvaluateWorkload runs every enabled workload rule against w. Violations are ordered by
// catalog order, then container order.
func EvaluateWorkload(w Workload, s Settings) []Violation {
	if w.Spec == nil {
		return nil
	}
	p := newPodView(w)
	var out []Violation
	for _, m := range Catalog {
		check, ok := workloadChecks[m.ID]
		if !ok || !s.Enabled(m.ID) {
			continue
		}
		for _, h := range check(p) {
			out = append(out, Violation{RuleID: m.ID, Severity: s.Severity(m.ID), Container: h.container, Evidence: h.evidence})
		}
	}
	return out
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

func checkPrivileged(p *podView) (hits []hit) {
	for _, c := range p.containers {
		if c.sc != nil && isTrue(c.sc.Privileged) {
			hits = append(hits, hit{c.name, c.path + ".securityContext.privileged is true"})
		}
	}
	return hits
}

func checkPrivilegeEscalation(p *podView) (hits []hit) {
	if !p.linux {
		return nil
	}
	for _, c := range p.containers {
		switch {
		case c.sc == nil || c.sc.AllowPrivilegeEscalation == nil:
			hits = append(hits, hit{c.name, c.path + ".securityContext.allowPrivilegeEscalation is not set (defaults to true)"})
		case *c.sc.AllowPrivilegeEscalation:
			hits = append(hits, hit{c.name, c.path + ".securityContext.allowPrivilegeEscalation is true"})
		}
	}
	return hits
}

// checkRunAsRoot follows the kubelet: a container runAsUser or runAsNonRoot overrides the
// pod's. A non-zero runAsUser is enough on its own; otherwise runAsNonRoot must be true.
// The image's USER is unknown here, so an unset user is reported as "may run as root".
func checkRunAsRoot(p *podView) (hits []hit) {
	if !p.linux {
		return nil
	}
	psc := p.Spec.SecurityContext
	for _, c := range p.containers {
		uid, uidPath := (*int64)(nil), ""
		nonRoot := (*bool)(nil)
		if c.sc != nil {
			uid, nonRoot = c.sc.RunAsUser, c.sc.RunAsNonRoot
			uidPath = c.path + ".securityContext.runAsUser"
		}
		if psc != nil {
			if uid == nil && psc.RunAsUser != nil {
				uid, uidPath = psc.RunAsUser, p.SpecPath+".securityContext.runAsUser"
			}
			if nonRoot == nil {
				nonRoot = psc.RunAsNonRoot
			}
		}
		switch {
		case uid != nil && *uid == 0:
			hits = append(hits, hit{c.name, uidPath + " is 0"})
		case uid == nil && !isTrue(nonRoot):
			hits = append(hits, hit{c.name, "neither runAsNonRoot: true nor a non-zero runAsUser is set for " + c.path +
				" or in " + p.SpecPath + ".securityContext"})
		}
	}
	return hits
}

func checkReadOnlyRootFilesystem(p *podView) (hits []hit) {
	if !p.linux {
		return nil
	}
	for _, c := range p.containers {
		if c.sc == nil || !isTrue(c.sc.ReadOnlyRootFilesystem) {
			hits = append(hits, hit{c.name, c.path + ".securityContext.readOnlyRootFilesystem is not true"})
		}
	}
	return hits
}

// normalizeCapability turns "cap_sys_admin" and "SYS_ADMIN" into "SYS_ADMIN".
func normalizeCapability(c corev1.Capability) string {
	return strings.TrimPrefix(strings.ToUpper(string(c)), "CAP_")
}

func checkDropCapabilities(p *podView) (hits []hit) {
	if !p.linux {
		return nil
	}
	for _, c := range p.containers {
		var drop []corev1.Capability
		if c.sc != nil && c.sc.Capabilities != nil {
			drop = c.sc.Capabilities.Drop
		}
		if !slices.ContainsFunc(drop, func(d corev1.Capability) bool { return normalizeCapability(d) == "ALL" }) {
			hits = append(hits, hit{c.name, c.path + ".securityContext.capabilities.drop does not include ALL"})
		}
	}
	return hits
}

// dangerousCapabilities grant control over the host, the kernel or other processes.
var dangerousCapabilities = []string{
	"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "SYS_BOOT", "SYS_TIME",
	"NET_ADMIN", "NET_RAW", "DAC_READ_SEARCH", "BPF", "PERFMON", "MAC_ADMIN", "MAC_OVERRIDE",
}

func checkDangerousCapabilities(p *podView) (hits []hit) {
	if !p.linux {
		return nil
	}
	for _, c := range p.containers {
		if c.sc == nil || c.sc.Capabilities == nil {
			continue
		}
		var found []string
		for _, a := range c.sc.Capabilities.Add {
			if n := normalizeCapability(a); slices.Contains(dangerousCapabilities, n) && !slices.Contains(found, n) {
				found = append(found, n)
			}
		}
		if len(found) > 0 {
			hits = append(hits, hit{c.name, c.path + ".securityContext.capabilities.add includes " + strings.Join(found, ", ")})
		}
	}
	return hits
}

// checkSeccompProfile accepts RuntimeDefault and Localhost, set on the container or
// inherited from the pod.
func checkSeccompProfile(p *podView) (hits []hit) {
	if !p.linux {
		return nil
	}
	for _, c := range p.containers {
		profile, path := (*corev1.SeccompProfile)(nil), ""
		if c.sc != nil && c.sc.SeccompProfile != nil {
			profile, path = c.sc.SeccompProfile, c.path+".securityContext.seccompProfile.type"
		} else if psc := p.Spec.SecurityContext; psc != nil && psc.SeccompProfile != nil {
			profile, path = psc.SeccompProfile, p.SpecPath+".securityContext.seccompProfile.type"
		}
		switch {
		case profile == nil:
			hits = append(hits, hit{c.name, "no seccompProfile is set for " + c.path + " or in " + p.SpecPath +
				".securityContext (Unconfined unless the kubelet enables RuntimeDefault)"})
		case profile.Type == corev1.SeccompProfileTypeUnconfined:
			hits = append(hits, hit{c.name, path + " is Unconfined"})
		}
	}
	return hits
}

func podFlag(field string, get func(*corev1.PodSpec) bool) workloadCheck {
	return func(p *podView) []hit {
		if get(p.Spec) {
			return []hit{{"", p.SpecPath + "." + field + " is true"}}
		}
		return nil
	}
}

// ImageTag returns the tag of an image reference and whether it is pinned by digest.
// A registry port is not a tag: "registry:5000/app" has no tag.
func ImageTag(image string) (tag string, digest bool) {
	if strings.Contains(image, "@") {
		return "", true
	}
	name := image[strings.LastIndex(image, "/")+1:]
	_, tag, _ = strings.Cut(name, ":")
	return tag, false
}

func checkLatestTag(p *podView) (hits []hit) {
	for _, c := range p.containers {
		if tag, digest := ImageTag(c.image); !digest && tag == "latest" {
			hits = append(hits, hit{c.name, fmt.Sprintf("%s.image is %q", c.path, c.image)})
		}
	}
	return hits
}

func checkImplicitTag(p *podView) (hits []hit) {
	for _, c := range p.containers {
		if c.image == "" {
			continue
		}
		if tag, digest := ImageTag(c.image); !digest && tag == "" {
			hits = append(hits, hit{c.name, fmt.Sprintf("%s.image is %q, which has no tag (pulls latest)", c.path, c.image)})
		}
	}
	return hits
}

// checkServiceAccountToken follows the kubelet: the pod field wins, then the
// ServiceAccount's, and the token is mounted when neither disables it.
func checkServiceAccountToken(p *podView) []hit {
	if v := p.Spec.AutomountServiceAccountToken; v != nil {
		if *v {
			return []hit{{"", p.SpecPath + ".automountServiceAccountToken is true"}}
		}
		return nil
	}
	sa := ServiceAccountName(p.Spec)
	if p.ServiceAccount != nil && p.ServiceAccount.AutomountServiceAccountToken != nil {
		if isFalse(p.ServiceAccount.AutomountServiceAccountToken) {
			return nil
		}
		return []hit{{"", fmt.Sprintf("ServiceAccount %q sets automountServiceAccountToken: true and %s does not override it",
			sa, p.SpecPath)}}
	}
	return []hit{{"", fmt.Sprintf("%s.automountServiceAccountToken is not set and ServiceAccount %q does not disable it (defaults to true)",
		p.SpecPath, sa)}}
}

func checkDefaultServiceAccount(p *podView) []hit {
	if ServiceAccountName(p.Spec) != "default" {
		return nil
	}
	if p.Spec.ServiceAccountName == "" && p.Spec.DeprecatedServiceAccount == "" {
		return []hit{{"", p.SpecPath + ".serviceAccountName is not set, so the pods run as \"default\""}}
	}
	return []hit{{"", p.SpecPath + ".serviceAccountName is \"default\""}}
}
