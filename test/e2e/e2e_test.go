//go:build e2e
// +build e2e

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
		for _, r := range []string{"deployments.apps", "pods", "clusterroles.rbac.authorization.k8s.io", "networkpolicies.networking.k8s.io"} {
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
})
