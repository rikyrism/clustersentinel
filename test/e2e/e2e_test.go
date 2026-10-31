//go:build e2e

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

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rikyrism/clustersentinel/test/utils"
)

const (
	namespace          = "clustersentinel-system"
	serviceAccountName = "clustersentinel-controller-manager"
	metricsServiceName = "clustersentinel-controller-manager-metrics-service"
)

func kubectl(args ...string) (string, error) {
	return utils.Run(exec.Command("kubectl", args...))
}

func kubectlApply(manifest string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	return err
}

// analysisLog is one "Analysis result changed" line of the operator's JSON log.
type analysisLog struct {
	Msg               string   `json:"msg"`
	ResourceKind      string   `json:"resourceKind"`
	ResourceNamespace string   `json:"resourceNamespace"`
	ResourceName      string   `json:"resourceName"`
	Violations        int      `json:"violations"`
	Rules             []string `json:"rules"`
}

// lastAnalysis returns the latest analysis logged for a resource, or nil.
func lastAnalysis(g Gomega, pod, kind, resNamespace, name string) *analysisLog {
	out, err := kubectl("logs", pod, "-n", namespace)
	g.Expect(err).NotTo(HaveOccurred())
	var last *analysisLog
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l analysisLog
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.Msg != "Analysis result changed" {
			continue
		}
		if l.ResourceKind == kind && l.ResourceNamespace == resNamespace && l.ResourceName == name {
			last = &l
		}
	}
	return last
}

// findingStates returns the state of each SecurityFinding of a rule on a resource, as
// "<rule>=<state>" sorted by kubectl's output order.
func findingStates(g Gomega, findingNamespace, ruleID, resourceName string) []string {
	out, err := kubectl("get", "securityfindings", "-n", findingNamespace,
		"-l", "security.clustersentinel.io/rule-id="+ruleID, "-o",
		`jsonpath={range .items[?(@.spec.resource.name=="`+resourceName+`")]}{.spec.ruleID}={.status.state}{"\n"}{end}`)
	g.Expect(err).NotTo(HaveOccurred())
	return strings.Fields(out)
}

const workloadsNamespace = "e2e-workloads"

// webDeployment renders a Deployment; insecure adds a privileged container on a latest image.
func webDeployment(insecure bool) string {
	image, sc := "registry.k8s.io/pause:3.10", `
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}`
	if insecure {
		image, sc = "registry.k8s.io/pause:latest", `
            privileged: true`
	}
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: %s
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: app
          image: %s
          securityContext:%s
`, workloadsNamespace, image, sc)
}

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	BeforeAll(func() {
		By("creating the manager namespace with the restricted Pod Security Standard")
		_, err := kubectl("create", "ns", namespace)
		Expect(err).NotTo(HaveOccurred())
		_, err = kubectl("label", "--overwrite", "ns", namespace, "pod-security.kubernetes.io/enforce=restricted")
		Expect(err).NotTo(HaveOccurred())

		By("installing CRDs and deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", managerImage)))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		_, _ = utils.Run(exec.Command("make", "undeploy", "ignore-not-found=true"))
		_, _ = utils.Run(exec.Command("make", "uninstall", "ignore-not-found=true"))
		_, _ = kubectl("delete", "ns", namespace, "--ignore-not-found")
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() || controllerPodName == "" {
			return
		}
		for _, args := range [][]string{
			{"logs", controllerPodName, "-n", namespace},
			{"get", "events", "-n", namespace, "--sort-by=.lastTimestamp"},
			{"describe", "pod", controllerPodName, "-n", namespace},
		} {
			out, err := kubectl(args...)
			_, _ = fmt.Fprintf(GinkgoWriter, "kubectl %s:\n%s %v\n", strings.Join(args, " "), out, err)
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	It("runs one ready controller pod", func() {
		Eventually(func(g Gomega) {
			out, err := kubectl("get", "pods", "-n", namespace, "-l", "control-plane=controller-manager",
				"-o", "jsonpath={range .items[?(@.status.phase=='Running')]}{.metadata.name}{'\\n'}{end}")
			g.Expect(err).NotTo(HaveOccurred())
			names := utils.GetNonEmptyLines(out)
			g.Expect(names).To(HaveLen(1))
			controllerPodName = names[0]
			ready, err := kubectl("get", "pod", controllerPodName, "-n", namespace,
				"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ready).To(Equal("True"))
		}).Should(Succeed())
	})

	It("runs hardened", func() {
		get := func(path string) string {
			out, err := kubectl("get", "pod", controllerPodName, "-n", namespace, "-o", "jsonpath="+path)
			Expect(err).NotTo(HaveOccurred())
			return out
		}
		Expect(get("{.spec.securityContext.runAsNonRoot}")).To(Equal("true"))
		Expect(get("{.spec.securityContext.seccompProfile.type}")).To(Equal("RuntimeDefault"))
		Expect(get("{.spec.containers[0].securityContext.readOnlyRootFilesystem}")).To(Equal("true"))
		Expect(get("{.spec.containers[0].securityContext.allowPrivilegeEscalation}")).To(Equal("false"))
		Expect(get("{.spec.containers[0].securityContext.capabilities.drop}")).To(ContainSubstring("ALL"))
		Expect(get("{.spec.hostNetwork}{.spec.hostPID}{.spec.hostIPC}")).To(BeEmpty())
		Expect(get("{.spec.containers[0].resources.limits.memory}")).NotTo(BeEmpty())
	})

	It("serves Prometheus metrics", func() {
		Eventually(func(g Gomega) {
			out, err := kubectl("get", "--raw",
				fmt.Sprintf("/api/v1/namespaces/%s/services/http:%s:8080/proxy/metrics", namespace, metricsServiceName))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring("go_memstats_heap_inuse_bytes"))
		}).Should(Succeed())
	})

	It("has read-only access to workloads and no access to Secrets or RBAC writes", func() {
		as := fmt.Sprintf("--as=system:serviceaccount:%s:%s", namespace, serviceAccountName)
		canI := func(verb, resource string) string {
			out, _ := kubectl("auth", "can-i", verb, resource, "-A", as)
			return strings.TrimSpace(out)
		}
		for _, r := range []string{
			"deployments.apps", "replicasets.apps", "pods",
			"clusterroles.rbac.authorization.k8s.io", "networkpolicies.networking.k8s.io",
		} {
			Expect(canI("watch", r)).To(Equal("yes"), "watch "+r)
		}
		for _, check := range [][2]string{
			{"create", "deployments.apps"}, {"patch", "deployments.apps"}, {"delete", "pods"},
			{"update", "pods"}, {"get", "secrets"}, {"list", "secrets"},
			{"create", "clusterrolebindings.rbac.authorization.k8s.io"}, {"escalate", "clusterroles.rbac.authorization.k8s.io"},
		} {
			Expect(canI(check[0], check[1])).To(Equal("no"), check[0]+" "+check[1])
		}
		Expect(canI("create", "securityfindings.security.clustersentinel.io")).To(Equal("yes"))
	})

	Context("scanning", func() {
		BeforeAll(func() {
			_, err := kubectl("create", "ns", workloadsNamespace)
			Expect(err).NotTo(HaveOccurred())
		})
		AfterAll(func() {
			_, _ = kubectl("delete", "clusterrolebinding", "e2e-ci-admin", "--ignore-not-found")
			_, _ = kubectl("delete", "ns", workloadsNamespace, "--ignore-not-found", "--wait=false")
		})

		It("detects an insecure Deployment and clears it once fixed", func() {
			Expect(kubectlApply(webDeployment(true))).To(Succeed())
			Eventually(func(g Gomega) {
				l := lastAnalysis(g, controllerPodName, "Deployment", workloadsNamespace, "web")
				g.Expect(l).NotTo(BeNil())
				g.Expect(l.Rules).To(ContainElements("CS-CONTAINER-001/app", "CS-CONTAINER-002/app", "CS-IMAGE-001/app"))
			}).Should(Succeed())

			By("writing a SecurityFinding owned by the Deployment")
			Eventually(func(g Gomega) {
				g.Expect(findingStates(g, workloadsNamespace, "CS-CONTAINER-001", "web")).To(Equal([]string{"CS-CONTAINER-001=Open"}))
			}).Should(Succeed())
			out, err := kubectl("get", "securityfindings", "-n", workloadsNamespace,
				"-l", "security.clustersentinel.io/rule-id=CS-CONTAINER-001", "-o", "jsonpath={.items[0].metadata.ownerReferences[0].kind}")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(Equal("Deployment"))

			Expect(kubectlApply(webDeployment(false))).To(Succeed())
			Eventually(func(g Gomega) {
				l := lastAnalysis(g, controllerPodName, "Deployment", workloadsNamespace, "web")
				g.Expect(l).NotTo(BeNil())
				g.Expect(l.Violations).To(BeZero(), "rules still reported: %v", l.Rules)
			}).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(findingStates(g, workloadsNamespace, "CS-CONTAINER-001", "web")).To(Equal([]string{"CS-CONTAINER-001=Resolved"}))
			}).Should(Succeed())

			By("analyzing the template, not each replica")
			out, err = kubectl("logs", controllerPodName, "-n", namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(ContainSubstring(`"resourceKind":"Pod","resourceNamespace":"` + workloadsNamespace))
			Expect(out).NotTo(ContainSubstring(`"resourceKind":"ReplicaSet","resourceNamespace":"` + workloadsNamespace))

			By("deleting the findings with the Deployment")
			_, err = kubectl("delete", "deployment", "web", "-n", workloadsNamespace)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(findingStates(g, workloadsNamespace, "CS-CONTAINER-001", "web")).To(BeEmpty())
			}).Should(Succeed())
		})

		It("detects a cluster-admin binding and ignores the installer's admin group", func() {
			_, err := kubectl("create", "clusterrolebinding", "e2e-ci-admin", "--clusterrole=cluster-admin",
				"--serviceaccount="+workloadsNamespace+":ci")
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				l := lastAnalysis(g, controllerPodName, "ClusterRoleBinding", "", "e2e-ci-admin")
				g.Expect(l).NotTo(BeNil())
				g.Expect(l.Rules).To(Equal([]string{"CS-RBAC-002"}))
			}).Should(Succeed())
			out, err := kubectl("logs", controllerPodName, "-n", namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(ContainSubstring(`"resourceName":"kubeadm:cluster-admins"`))

			By("keeping findings about cluster-scoped objects in the operator namespace")
			Eventually(func(g Gomega) {
				g.Expect(findingStates(g, namespace, "CS-RBAC-002", "e2e-ci-admin")).To(Equal([]string{"CS-RBAC-002=Open"}))
			}).Should(Succeed())
			_, err = kubectl("delete", "clusterrolebinding", "e2e-ci-admin")
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(findingStates(g, namespace, "CS-RBAC-002", "e2e-ci-admin")).To(BeEmpty())
			}).Should(Succeed())
		})

		It("summarizes the cluster in the SecurityReport", func() {
			Eventually(func(g Gomega) {
				out, err := kubectl("get", "securityreport", "cluster", "-n", namespace, "-o",
					`jsonpath={.status.conditions[?(@.type=="ScannerHealthy")].status} {.status.scannedResources}`)
				g.Expect(err).NotTo(HaveOccurred())
				fields := strings.Fields(out)
				g.Expect(fields).To(HaveLen(2))
				g.Expect(fields[0]).To(Equal("True"))
				g.Expect(fields[1]).NotTo(Equal("0"))
			}, 2*time.Minute).Should(Succeed())
		})
	})
})
