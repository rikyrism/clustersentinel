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
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
)

const specPath = "spec.template.spec"

// hardenedSpec passes every workload rule.
func hardenedSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		ServiceAccountName:           "app",
		AutomountServiceAccountToken: new(false),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   new(true),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:  "app",
			Image: "registry.example.com:5000/team/app:1.4.2",
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: new(false),
				ReadOnlyRootFilesystem:   new(true),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
		}},
	}
}

func strict() Settings { return NewSettings(securityv1alpha1.ProfileStrict, nil) }

func evaluate(spec *corev1.PodSpec) []Violation {
	return EvaluateWorkload(Workload{SpecPath: specPath, Spec: spec}, strict())
}

// only returns the violations of one rule.
func only(vs []Violation, id string) []Violation {
	return slices.DeleteFunc(slices.Clone(vs), func(v Violation) bool { return v.RuleID != id })
}

func TestHardenedSpecPassesEveryRule(t *testing.T) {
	if vs := evaluate(hardenedSpec()); len(vs) != 0 {
		t.Fatalf("expected no violations, got %+v", vs)
	}
}

func TestEveryWorkloadRuleHasACheck(t *testing.T) {
	for _, m := range Catalog {
		if _, ok := workloadChecks[m.ID]; ok != (m.Scope == ScopeWorkload) {
			t.Errorf("%s: scope %s, has workload check: %v", m.ID, m.Scope, ok)
		}
	}
}

func TestWorkloadRules(t *testing.T) {
	sc := func(s *corev1.PodSpec) *corev1.SecurityContext { return s.Containers[0].SecurityContext }
	cases := []struct {
		name   string
		rule   string
		mutate func(s *corev1.PodSpec)
		// want is a substring of the evidence; empty means no violation is expected.
		want string
	}{
		{"privileged", IDPrivileged, func(s *corev1.PodSpec) { sc(s).Privileged = new(true) },
			"spec.template.spec.containers[0].securityContext.privileged is true"},
		{"privileged false", IDPrivileged, func(s *corev1.PodSpec) { sc(s).Privileged = new(false) }, ""},
		{"privileged init container", IDPrivileged, func(s *corev1.PodSpec) {
			s.InitContainers = []corev1.Container{{Name: "init", Image: "busybox:1.36",
				SecurityContext: &corev1.SecurityContext{Privileged: new(true)}}}
		}, "spec.template.spec.initContainers[0].securityContext.privileged is true"},
		{"privileged ephemeral container", IDPrivileged, func(s *corev1.PodSpec) {
			s.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: "debug", Image: "busybox:1.36", SecurityContext: &corev1.SecurityContext{Privileged: new(true)}}}}
		}, "ephemeralContainers[0].securityContext.privileged is true"},

		{"escalation unset", IDPrivilegeEscalation, func(s *corev1.PodSpec) { sc(s).AllowPrivilegeEscalation = nil },
			"allowPrivilegeEscalation is not set (defaults to true)"},
		{"escalation no securityContext", IDPrivilegeEscalation, func(s *corev1.PodSpec) { s.Containers[0].SecurityContext = nil },
			"allowPrivilegeEscalation is not set"},
		{"escalation true", IDPrivilegeEscalation, func(s *corev1.PodSpec) { sc(s).AllowPrivilegeEscalation = new(true) },
			"allowPrivilegeEscalation is true"},

		{"root: nothing set", IDRunAsRoot, func(s *corev1.PodSpec) { s.SecurityContext.RunAsNonRoot = nil },
			"neither runAsNonRoot: true nor a non-zero runAsUser"},
		{"root: pod runAsUser 0", IDRunAsRoot, func(s *corev1.PodSpec) { s.SecurityContext.RunAsUser = ptr.To[int64](0) },
			"spec.template.spec.securityContext.runAsUser is 0"},
		{"root: container runAsUser 0 overrides pod", IDRunAsRoot, func(s *corev1.PodSpec) {
			s.SecurityContext.RunAsUser = ptr.To[int64](1000)
			sc(s).RunAsUser = ptr.To[int64](0)
		}, "containers[0].securityContext.runAsUser is 0"},
		{"root: container non-zero uid overrides pod 0", IDRunAsRoot, func(s *corev1.PodSpec) {
			s.SecurityContext.RunAsUser = ptr.To[int64](0)
			sc(s).RunAsUser = ptr.To[int64](1000)
		}, ""},
		{"root: non-zero uid without runAsNonRoot", IDRunAsRoot, func(s *corev1.PodSpec) {
			s.SecurityContext.RunAsNonRoot = nil
			s.SecurityContext.RunAsUser = ptr.To[int64](65532)
		}, ""},
		{"root: container runAsNonRoot false overrides pod true", IDRunAsRoot, func(s *corev1.PodSpec) {
			sc(s).RunAsNonRoot = new(false)
		}, "neither runAsNonRoot"},
		{"root: container runAsNonRoot without pod context", IDRunAsRoot, func(s *corev1.PodSpec) {
			s.SecurityContext = nil
			sc(s).RunAsNonRoot = new(true)
		}, ""},

		{"writable root fs", IDReadOnlyRootFilesystem, func(s *corev1.PodSpec) { sc(s).ReadOnlyRootFilesystem = nil },
			"readOnlyRootFilesystem is not true"},
		{"read-only root fs false", IDReadOnlyRootFilesystem, func(s *corev1.PodSpec) { sc(s).ReadOnlyRootFilesystem = new(false) },
			"readOnlyRootFilesystem is not true"},

		{"capabilities not dropped", IDDropCapabilities, func(s *corev1.PodSpec) { sc(s).Capabilities = nil },
			"capabilities.drop does not include ALL"},
		{"only some capabilities dropped", IDDropCapabilities, func(s *corev1.PodSpec) {
			sc(s).Capabilities.Drop = []corev1.Capability{"NET_RAW"}
		}, "does not include ALL"},
		{"drop all lower case", IDDropCapabilities, func(s *corev1.PodSpec) {
			sc(s).Capabilities.Drop = []corev1.Capability{"all"}
		}, ""},

		{"dangerous capabilities", IDDangerousCapabilities, func(s *corev1.PodSpec) {
			sc(s).Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE", "CAP_SYS_ADMIN", "net_admin", "SYS_ADMIN"}
		}, "capabilities.add includes SYS_ADMIN, NET_ADMIN"},
		{"harmless capability", IDDangerousCapabilities, func(s *corev1.PodSpec) {
			sc(s).Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
		}, ""},

		{"no seccomp profile", IDSeccompProfile, func(s *corev1.PodSpec) { s.SecurityContext.SeccompProfile = nil },
			"no seccompProfile is set for spec.template.spec.containers[0]"},
		{"pod seccomp unconfined", IDSeccompProfile, func(s *corev1.PodSpec) {
			s.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
		}, "spec.template.spec.securityContext.seccompProfile.type is Unconfined"},
		{"container unconfined overrides pod", IDSeccompProfile, func(s *corev1.PodSpec) {
			sc(s).SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}, "containers[0].securityContext.seccompProfile.type is Unconfined"},
		{"container localhost profile", IDSeccompProfile, func(s *corev1.PodSpec) {
			s.SecurityContext.SeccompProfile = nil
			sc(s).SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: new("p.json")}
		}, ""},

		{"host network", IDHostNetwork, func(s *corev1.PodSpec) { s.HostNetwork = true }, "spec.template.spec.hostNetwork is true"},
		{"host PID", IDHostPID, func(s *corev1.PodSpec) { s.HostPID = true }, "spec.template.spec.hostPID is true"},
		{"host IPC", IDHostIPC, func(s *corev1.PodSpec) { s.HostIPC = true }, "spec.template.spec.hostIPC is true"},

		{"latest tag", IDLatestImageTag, func(s *corev1.PodSpec) { s.Containers[0].Image = "nginx:latest" }, `image is "nginx:latest"`},
		{"latest tag behind registry port", IDLatestImageTag, func(s *corev1.PodSpec) {
			s.Containers[0].Image = "registry:5000/app:latest"
		}, "registry:5000/app:latest"},
		{"latest pinned by digest", IDLatestImageTag, func(s *corev1.PodSpec) {
			s.Containers[0].Image = "nginx:latest@sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}, ""},
		{"implicit tag", IDImplicitImageTag, func(s *corev1.PodSpec) { s.Containers[0].Image = "nginx" }, "has no tag"},
		{"implicit tag with registry port", IDImplicitImageTag, func(s *corev1.PodSpec) {
			s.Containers[0].Image = "registry:5000/team/app"
		}, `"registry:5000/team/app", which has no tag`},
		{"digest without tag", IDImplicitImageTag, func(s *corev1.PodSpec) {
			s.Containers[0].Image = "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}, ""},

		{"token automount unset", IDServiceAccountToken, func(s *corev1.PodSpec) { s.AutomountServiceAccountToken = nil },
			`automountServiceAccountToken is not set and ServiceAccount "app" does not disable it`},
		{"token automount true", IDServiceAccountToken, func(s *corev1.PodSpec) { s.AutomountServiceAccountToken = new(true) },
			"spec.template.spec.automountServiceAccountToken is true"},

		{"default service account", IDDefaultServiceAccount, func(s *corev1.PodSpec) { s.ServiceAccountName = "default" },
			`serviceAccountName is "default"`},
		{"no service account", IDDefaultServiceAccount, func(s *corev1.PodSpec) { s.ServiceAccountName = "" },
			`serviceAccountName is not set, so the pods run as "default"`},
		{"deprecated serviceAccount field", IDDefaultServiceAccount, func(s *corev1.PodSpec) {
			s.ServiceAccountName = ""
			s.DeprecatedServiceAccount = "app"
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := hardenedSpec()
			tc.mutate(spec)
			vs := only(evaluate(spec), tc.rule)
			if tc.want == "" {
				if len(vs) != 0 {
					t.Fatalf("expected no %s violation, got %+v", tc.rule, vs)
				}
				return
			}
			if len(vs) != 1 {
				t.Fatalf("expected one %s violation, got %+v", tc.rule, vs)
			}
			if !strings.Contains(vs[0].Evidence, tc.want) {
				t.Fatalf("evidence %q does not contain %q", vs[0].Evidence, tc.want)
			}
			if vs[0].Severity != strict().Severity(tc.rule) {
				t.Fatalf("severity %s, want %s", vs[0].Severity, strict().Severity(tc.rule))
			}
		})
	}
}

func TestContainerRulesReportEachContainer(t *testing.T) {
	spec := hardenedSpec()
	spec.InitContainers = []corev1.Container{{Name: "init", Image: "busybox:1.36"}}
	spec.Containers = append(spec.Containers, corev1.Container{Name: "sidecar", Image: "envoy:1.30"})
	vs := only(evaluate(spec), IDReadOnlyRootFilesystem)
	got := make([]string, 0, len(vs))
	for _, v := range vs {
		got = append(got, v.Container)
	}
	if want := []string{"init", "sidecar"}; !slices.Equal(got, want) {
		t.Fatalf("containers = %v, want %v", got, want)
	}
}

func TestPodLevelRulesHaveNoContainer(t *testing.T) {
	spec := hardenedSpec()
	spec.HostNetwork = true
	for _, v := range only(evaluate(spec), IDHostNetwork) {
		if v.Container != "" {
			t.Fatalf("host network violation has container %q", v.Container)
		}
	}
}

func TestServiceAccountTokenFollowsServiceAccount(t *testing.T) {
	spec := hardenedSpec()
	spec.AutomountServiceAccountToken = nil
	run := func(sa *corev1.ServiceAccount) []Violation {
		return only(EvaluateWorkload(Workload{SpecPath: specPath, Spec: spec, ServiceAccount: sa}, strict()), IDServiceAccountToken)
	}
	if vs := run(&corev1.ServiceAccount{AutomountServiceAccountToken: new(false)}); len(vs) != 0 {
		t.Fatalf("ServiceAccount disables automount, got %+v", vs)
	}
	if vs := run(&corev1.ServiceAccount{AutomountServiceAccountToken: new(true)}); len(vs) != 1 ||
		!strings.Contains(vs[0].Evidence, `ServiceAccount "app" sets automountServiceAccountToken: true`) {
		t.Fatalf("ServiceAccount enables automount, got %+v", vs)
	}
	if vs := run(&corev1.ServiceAccount{}); len(vs) != 1 {
		t.Fatalf("ServiceAccount leaves the default, got %+v", vs)
	}
	spec.AutomountServiceAccountToken = new(false)
	if vs := run(&corev1.ServiceAccount{AutomountServiceAccountToken: new(true)}); len(vs) != 0 {
		t.Fatalf("pod field must win over the ServiceAccount, got %+v", vs)
	}
}

func TestWindowsPodsSkipLinuxOnlyRules(t *testing.T) {
	spec := &corev1.PodSpec{
		OS:                           &corev1.PodOS{Name: corev1.Windows},
		ServiceAccountName:           "app",
		AutomountServiceAccountToken: new(false),
		Containers:                   []corev1.Container{{Name: "app", Image: "mcr.microsoft.com/windows/nanoserver:ltsc2022"}},
	}
	if vs := evaluate(spec); len(vs) != 0 {
		t.Fatalf("expected no violations for a Windows pod, got %+v", vs)
	}
}

func TestSettingsControlRulesAndSeverity(t *testing.T) {
	spec := hardenedSpec()
	spec.HostPID = true
	spec.ServiceAccountName = "default"

	basic := NewSettings(securityv1alpha1.ProfileBasic, nil)
	vs := EvaluateWorkload(Workload{SpecPath: specPath, Spec: spec}, basic)
	if len(vs) != 1 || vs[0].RuleID != IDHostPID || vs[0].Severity != securityv1alpha1.SeverityHigh {
		t.Fatalf("basic profile: got %+v", vs)
	}

	custom := NewSettings(securityv1alpha1.ProfileBasic, map[string]Override{
		"hostPID":               {Enabled: new(false)},
		"defaultServiceAccount": {Enabled: new(true), Severity: securityv1alpha1.SeverityMedium},
	})
	vs = EvaluateWorkload(Workload{SpecPath: specPath, Spec: spec}, custom)
	if len(vs) != 1 || vs[0].RuleID != IDDefaultServiceAccount || vs[0].Severity != securityv1alpha1.SeverityMedium {
		t.Fatalf("overrides: got %+v", vs)
	}

	if (Settings{}).AnyEnabled(strict().EnabledIDs()...) {
		t.Fatal("zero Settings must enable nothing")
	}
	if got := len(strict().EnabledIDs()); got != len(Catalog) {
		t.Fatalf("strict enables %d rules, want %d", got, len(Catalog))
	}
}

func TestImageTag(t *testing.T) {
	for image, want := range map[string]string{
		"nginx":                        "",
		"nginx:1.27":                   "1.27",
		"localhost:5000/app":           "",
		"localhost:5000/app:v2":        "v2",
		"ghcr.io/org/team/app:latest":  "latest",
		"docker.io/library/nginx:1.27": "1.27",
	} {
		if got, digest := ImageTag(image); got != want || digest {
			t.Errorf("ImageTag(%q) = %q, %v; want %q, false", image, got, digest, want)
		}
	}
	if _, digest := ImageTag("nginx@sha256:abc"); !digest {
		t.Error("digest reference not detected")
	}
}

func TestGuidanceCoversCatalog(t *testing.T) {
	for _, m := range Catalog {
		g := GuidanceFor(m.ID)
		if g.Description == "" || g.Recommendation == "" {
			t.Errorf("%s: missing guidance", m.ID)
		}
	}
	if len(guidance) != len(Catalog) {
		t.Errorf("guidance has %d entries for %d rules", len(guidance), len(Catalog))
	}
}
