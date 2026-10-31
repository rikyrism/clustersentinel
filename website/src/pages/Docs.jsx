import { useEffect, useState } from 'react'
import Layout from '../components/Layout.jsx'
import { Backdrop, Notice, QuickStart, Severity, Shell } from '../components/ui.jsx'
import rules from '../data/rules.json'
import { PHASES, PHASES_DONE, REPO } from '../data/site.js'

const TOC = [
  ['Getting started', [['overview', 'Overview'], ['status', 'Status'], ['quick-start', 'Install'], ['production', 'Production'], ['local', 'Try it locally']]],
  ['Concepts', [['how-it-works', 'How it works'], ['templates', 'Templates and Pods'], ['profiles', 'Profiles']]],
  ['Reference', [['configuration', 'Configuration'], ['rules', 'Rules'], ['security-model', 'Security model'],
    ['resources', 'Resource usage']]],
  ['Project', [['limitations', 'Limitations'], ['development', 'Development']]],
]

const CONFIG = [
  ['clusterName', 'kubernetes', 'Shown in reports and notifications.'],
  ['scanner.mode', 'audit', <>Only <code>audit</code> exists. Workloads are never changed.</>],
  ['scanner.scanInterval', '30m', <>Periodic rescan from the cache. <code>0</code> disables it; otherwise at least <code>1m</code>.</>],
  ['scanner.profile', 'recommended', <><code>basic</code>, <code>recommended</code>, <code>strict</code> or <code>custom</code>.</>],
  ['scanner.rules', 'empty', <>Rule key to <code>true</code> or <code>false</code>, applied on top of the profile. Keys are listed under <a href="#rules">Rules</a>.</>],
  ['scanner.namespaces.include', 'empty (all)', 'Only these namespaces are cached and analyzed.'],
  ['scanner.namespaces.exclude', '[kube-system]', <>Never transferred or cached: the API server filters them with a field selector. Wins over <code>include</code>.</>],
  ['scanner.maxConcurrentReconciles', '2', 'Parallel reconciles per controller, 1 to 16.'],
  ['scanner.resolvedRetention', '168h', 'How long Resolved findings are kept. Used from Phase 3.'],
  ['notifications.channels', 'empty', 'Discord, Slack or webhook channels. Validated today, sent from Phase 6.'],
]

const PROFILES = [
  ['basic', 'Rules that indicate a clear risk: privileged containers, privilege escalation, dangerous capabilities, host namespaces, cluster-admin bindings.'],
  ['recommended', <>basic, plus hardening: non-root, read-only root filesystem, dropped capabilities, seccomp, image tags, token automount, wildcard and broad RBAC. <strong>Default.</strong></>],
  ['strict', 'recommended, plus the default ServiceAccount and missing NetworkPolicy rules.'],
  ['custom', <>Nothing by itself. Only rules turned on in <code>scanner.rules</code> run.</>],
]

const RBAC = [
  ['Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, Pods, ServiceAccounts, Namespaces, Roles, ClusterRoles, bindings, NetworkPolicies',
    <><code>get</code> <code>list</code> <code>watch</code></>],
  ['SecurityPolicies', 'read, and update of their status'],
  ['SecurityFindings, SecurityReports', 'full access to its own objects'],
  ['Leases and Events in its namespace', 'leader election and events'],
  ['Secrets', <strong>none</strong>],
]

const DEV = [
  ['make test', 'Unit tests, CRD validation and controller tests against a real API server (envtest)'],
  ['make lint', 'golangci-lint'],
  ['make test-e2e', 'Creates a kind cluster, deploys the operator, checks hardening, metrics, RBAC and detection, then deletes it'],
  ['make run', <>Runs the operator locally against the <strong>current</strong> kubeconfig context; check it first</>],
  ['make manifests generate', 'Regenerates CRDs, RBAC and deepcopy code'],
  ['make site-data', 'Regenerates the rule data of this website from the rule catalog'],
]

const CONFIG_EXAMPLE = `clusterName: production
scanner:
  mode: audit
  scanInterval: 30m
  profile: recommended
  rules:
    runAsRoot: false            # turn one rule off
    missingNetworkPolicy: true  # or on
  namespaces:
    exclude: [kube-system]
  maxConcurrentReconciles: 2`

const LOKI_EXAMPLE = `{namespace="clustersentinel-system"} | json | msg="Analysis result changed" | violations > 0`

const CONFIGMAP_EXAMPLE = `# kubectl -n clustersentinel-system create configmap clustersentinel-config --from-file=config.yaml
# then add to the manager container in dist/install.yaml:
        args:
          - --leader-elect
          - --health-probe-bind-address=:8081
          - --config=/etc/clustersentinel/config.yaml
        volumeMounts:
          - name: config
            mountPath: /etc/clustersentinel
            readOnly: true
      volumes:
        - name: config
          configMap:
            name: clustersentinel-config`

const LOG_EXAMPLE = `{"msg":"Analysis result changed","resourceKind":"Pod","resourceNamespace":"demo",
 "resourceName":"debug","violations":8,"rules":["CS-CONTAINER-001/debug", ...]}`

function Table({ head, rows }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {rows.map((cells, i) => <tr key={i}>{cells.map((c, j) => <td key={j}>{c}</td>)}</tr>)}
        </tbody>
      </table>
    </div>
  )
}

/** Tracks the section in view, for the table of contents. */
function useActiveSection() {
  const [active, setActive] = useState('')
  useEffect(() => {
    // Content renders after load, so the browser neither jumps to a #fragment nor matches
    // :target on its own. Do both by hand, on load and on every hash change.
    const goToHash = () => {
      document.querySelectorAll('.is-target').forEach((el) => el.classList.remove('is-target'))
      const el = location.hash && document.getElementById(decodeURIComponent(location.hash.slice(1)))
      if (!el) return
      el.classList.add('is-target')
      el.scrollIntoView()
    }
    goToHash()
    addEventListener('hashchange', goToHash)
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) setActive(e.target.id)
    }, { rootMargin: '-80px 0px -70% 0px' })
    document.querySelectorAll('.doc section[id]').forEach((s) => io.observe(s))
    return () => {
      io.disconnect()
      removeEventListener('hashchange', goToHash)
    }
  }, [])
  return active
}

export default function Docs() {
  const active = useActiveSection()
  return (
    <Layout current="docs">
      <div className="docs-top" data-parallax><Backdrop /></div>
      <div className="container docs">
        <nav className="toc" aria-label="On this page">
          {TOC.map(([group, links]) => (
            <div key={group}>
              <div className="label">{group}</div>
              {links.map(([id, title]) => (
                <a key={id} href={`#${id}`} className={active === id ? 'active' : undefined}>{title}</a>
              ))}
            </div>
          ))}
        </nav>

        <article className="doc">
          <section id="overview">
            <span className="label accent">Documentation</span>
            <h1>ClusterSentinel</h1>
            <p>
              ClusterSentinel is a Kubernetes operator that audits the configuration of your workloads and RBAC. It
              watches Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, Pods, Roles, ClusterRoles,
              their bindings and namespaces, and checks them against {rules.length} built-in rules.
            </p>
            <p>
              It is <strong>read-only</strong>: it can list and watch what it audits, it cannot modify any of it, and it
              cannot read Secrets. It runs as one pod with no node agent and no database.
            </p>
          </section>

          <section id="status">
            <h2>Status</h2>
            <Notice label="Pre-alpha">
              Phase {PHASES_DONE} of {PHASES.length} is complete. This page documents what exists today and marks what is planned.
            </Notice>
            <ul>
              <li><strong>Works now:</strong> all {rules.length} rules, the controllers, namespace filtering, profiles and rule toggles in the operator configuration, periodic rescan. Results are written to the operator log when they change.</li>
              <li><strong>Phase 3:</strong> results become <code>SecurityFinding</code> resources, with automatic resolution and retention, and a cluster <code>SecurityReport</code>.</li>
              <li><strong>Later:</strong> per-namespace <code>SecurityPolicy</code>, the CLI, notifications, metrics and a Helm chart. See the <a href="/roadmap/">roadmap</a>.</li>
            </ul>
          </section>

          <section id="quick-start">
            <h2>Install on your cluster</h2>
            <p>
              ClusterSentinel talks to nothing but the Kubernetes API: no cloud credentials, no node access, no
              provider-specific code. The same manifests work on Amazon EKS, Google GKE, Azure AKS, DigitalOcean,
              k3s, on-premises clusters and any other conformant Kubernetes.
            </p>
            <Notice label="No release yet">
              There is no published image or Helm chart until Phase 7, so you build the image and push it to a
              registry your nodes can pull from: ECR, Artifact Registry, ACR, GHCR or your own. CI tests it on kind
              with Kubernetes 1.31 to 1.34; managed clusters are not part of CI yet.
            </Notice>
            <p>You need Go 1.26+, Docker with buildx, kubectl, and to be logged in to your registry.</p>
            <Shell
              title="your cluster"
              lines={[
                [`git clone ${REPO}.git && cd clustersentinel`],
                ['export IMG=<registry>/clustersentinel:dev', 'e.g. 123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/clustersentinel:dev'],
                ['make docker-buildx IMG=$IMG', 'builds amd64 and arm64 (Graviton, Ampere) and pushes'],
                ['make build-installer IMG=$IMG', 'writes CRDs, RBAC and the Deployment to dist/install.yaml'],
                ['kubectl config current-context', 'make sure this is the cluster you mean'],
                ['kubectl apply -f dist/install.yaml'],
                ['kubectl -n clustersentinel-system rollout status deploy/clustersentinel-controller-manager'],
              ]}
            />
            <p>Then watch the first scan. Each result is one JSON line, written when it changes:</p>
            <Shell
              lines={[
                ['kubectl -n clustersentinel-system logs deploy/clustersentinel-controller-manager | grep "Analysis result"'],
              ]}
            />
            <pre><code>{LOG_EXAMPLE}</code></pre>
            <ul>
              <li><strong>Review before applying.</strong> <code>dist/install.yaml</code> is plain YAML: one namespace, the CRDs, a read-only ClusterRole (see <a href="#security-model">Security model</a>) and one Deployment.</li>
              <li><strong>Private registry.</strong> On EKS, nodes pull from ECR in the same account with their node role. Elsewhere, add an <code>imagePullSecret</code> to the Deployment.</li>
              <li><strong>Admission policies.</strong> The pod already meets the <code>restricted</code> Pod Security Standard, so Kyverno, Gatekeeper or PSA in enforce mode should not block it.</li>
              <li><strong>Upgrade.</strong> Build with a new tag, run <code>make build-installer</code> again and apply.</li>
              <li><strong>Remove it.</strong> <code>kubectl delete -f dist/install.yaml</code> deletes everything it created, including the CRDs.</li>
            </ul>
          </section>

          <section id="production">
            <h2>Running in production</h2>
            <h3>Check that it really is read-only</h3>
            <p>Do not take the docs for it. Ask the API server what the operator&apos;s ServiceAccount may do:</p>
            <Shell
              lines={[
                ['kubectl auth can-i --list --as=system:serviceaccount:clustersentinel-system:clustersentinel-controller-manager'],
                ['kubectl auth can-i get secrets -A --as=system:serviceaccount:clustersentinel-system:clustersentinel-controller-manager', 'no'],
              ]}
            />

            <h3>Send the results to your log stack</h3>
            <p>
              Until findings become resources in Phase 3, the log is the result. It is structured JSON on stdout, so
              whatever already collects your pod logs picks it up: CloudWatch with Fluent Bit, Loki, Elasticsearch or
              Datadog. Filter on <code>msg</code> and alert on new <code>CRITICAL</code> or <code>HIGH</code> rules.
            </p>
            <pre><code>{LOKI_EXAMPLE}</code></pre>

            <h3>Tune what it looks at</h3>
            <ul>
              <li>Start with the default <code>recommended</code> profile. If the first scan is too noisy for an old cluster, use <code>basic</code> to fix the clear risks first.</li>
              <li>Add namespaces of add-ons you do not own to <code>scanner.namespaces.exclude</code>. Excluded namespaces are never sent to the operator.</li>
              <li>Set <code>clusterName</code> when you run it in several clusters, one install per cluster.</li>
            </ul>
            <p>
              The default manifests run with built-in defaults. To use a configuration file, put it in a ConfigMap,
              mount it and pass <code>--config</code>. The Helm chart will do this for you.
            </p>
            <pre><code>{CONFIGMAP_EXAMPLE}</code></pre>

            <h3>Size it</h3>
            <p>
              Requests are 25m CPU and 64Mi memory, limits 200m and 128Mi. The Go memory limit is set to 90% of the
              container limit. Memory grows with the number of objects it caches; on clusters with thousands of Pods
              it has not been measured yet, so watch it for the first day and raise the limit if needed. Leader
              election is on, so a second replica only waits as a standby.
            </p>
          </section>

          <section id="local">
            <h2>Try it locally</h2>
            <p>
              To look at it without a real cluster, run it on <a href="https://kind.sigs.k8s.io/">kind</a>. You need
              Go 1.26+, Docker, kind and kubectl. One command creates the cluster, builds and loads the image and
              deploys the operator.
            </p>
            <QuickStart />
            <p>
              The kind targets write their own kubeconfig to <code>bin/</code> and never read or change{' '}
              <code>~/.kube/config</code>. <code>make kind-down</code> deletes the cluster.
            </p>
          </section>

          <section id="how-it-works">
            <h2>How it works</h2>
            <ol>
              <li><strong>Watch.</strong> Controllers watch each audited resource type through a shared informer cache. The cache drops <code>managedFields</code> and <code>last-applied-configuration</code>, keeps only metadata for replica Pods, and never holds Secrets or ConfigMaps.</li>
              <li><strong>Evaluate.</strong> An object is analyzed when its spec changes (<code>metadata.generation</code>) or its controller changes. Status updates, which are most updates, are ignored.</li>
              <li><strong>Record.</strong> Each result is fingerprinted. If it did not change, nothing happens.</li>
              <li><strong>Rescan.</strong> Every <code>scanInterval</code> (default 30 minutes, with 10% jitter) every object is analyzed again from the cache, as a safety net. This makes no extra calls to the API server.</li>
            </ol>
            <p>
              Controllers whose rules are all disabled are not started, so their objects are never loaded. With the
              default profile, NetworkPolicies are not watched at all.
            </p>
          </section>

          <section id="templates">
            <h2>Templates and Pods</h2>
            <ul>
              <li><strong>Deployments, StatefulSets, DaemonSets and CronJobs</strong> are analyzed once, from their pod template.</li>
              <li><strong>Jobs</strong> created by a CronJob are skipped; standalone Jobs are analyzed.</li>
              <li><strong>ReplicaSets</strong> owned by a Deployment are skipped. Other ReplicaSets, such as those of Argo Rollouts, are analyzed while they have replicas.</li>
              <li><strong>Standalone and static Pods</strong> are analyzed one by one.</li>
              <li><strong>Pods of other controllers</strong> (operators, custom resources) are analyzed as one group per controller and reported against the controller.</li>
            </ul>
          </section>

          <section id="profiles">
            <h2>Profiles</h2>
            <Table head={['Profile', 'Enables']} rows={PROFILES.map(([p, d]) => [<code key={p}>{p}</code>, d])} />
          </section>

          <section id="configuration">
            <h2>Configuration</h2>
            <p>
              The operator reads a YAML file passed with <code>--config</code>. Without one, the defaults below apply.
              Unknown keys are rejected, and every error is reported at once on start.
            </p>
            <pre><code>{CONFIG_EXAMPLE}</code></pre>
            <Table
              head={['Key', 'Default', 'Description']}
              rows={CONFIG.map(([k, d, text]) => [<code key="k">{k}</code>, <code key="d">{d}</code>, text])}
            />
            <p>
              Cluster-scoped objects (ClusterRoles, ClusterRoleBindings) are always evaluated. Namespaced RBAC
              follows the namespace selection.
            </p>
          </section>

          <section id="rules">
            <h2>Rules</h2>
            <p>
              Every rule has a stable ID, a key used in configuration, a default severity and the profiles that enable
              it. Container settings are read from the container first, then the pod, as the kubelet does. Init and
              ephemeral containers are checked like regular ones. Windows Pods skip the Linux-only rules.
            </p>
            {rules.map((r) => (
              <article className="rule" id={r.id.toLowerCase()} key={r.id}>
                <div className="row"><code>{r.id}</code><Severity level={r.severity} /></div>
                <h3>{r.name}</h3>
                <p>{r.description}</p>
                <p className="fix"><strong>Fix:</strong> {r.recommendation}</p>
                <div className="meta">key: {r.key} · profiles: {r.profiles.join(', ')} · scope: {r.scope.toLowerCase()}</div>
              </article>
            ))}
            <h3>Details that affect results</h3>
            <ul>
              <li>A non-zero <code>runAsUser</code> passes the root rule on its own; otherwise <code>runAsNonRoot: true</code> is needed. The image's <code>USER</code> is not known, so the rule says "may run as root".</li>
              <li>A registry port is not a tag: <code>registry:5000/app</code> has no tag. Images pinned by digest pass both image rules.</li>
              <li>Dangerous capabilities: <code>ALL</code>, <code>SYS_ADMIN</code>, <code>SYS_MODULE</code>, <code>SYS_PTRACE</code>, <code>SYS_RAWIO</code>, <code>SYS_BOOT</code>, <code>SYS_TIME</code>, <code>NET_ADMIN</code>, <code>NET_RAW</code>, <code>DAC_READ_SEARCH</code>, <code>BPF</code>, <code>PERFMON</code>, <code>MAC_ADMIN</code>, <code>MAC_OVERRIDE</code>.</li>
              <li>Built-in RBAC (label <code>kubernetes.io/bootstrapping=rbac-defaults</code> or a <code>system:</code> name) and aggregated ClusterRoles are not evaluated. Kubernetes reserves the <code>system:</code> prefix but does not enforce it.</li>
              <li>cluster-admin bound to <code>system:masters</code> or <code>kubeadm:cluster-admins</code> is expected and not reported. RoleBindings to cluster-admin are reported with their namespace.</li>
              <li>The NetworkPolicy rule only checks that a namespace with Pods has at least one NetworkPolicy. It is a hint, not proof that traffic is restricted.</li>
            </ul>
          </section>

          <section id="security-model">
            <h2>Security model</h2>
            <Table head={['Resources', 'Access']} rows={RBAC} />
            <p>
              The ClusterRole is generated from{' '}
              <a href={`${REPO}/blob/main/internal/manager/rbac.go`}><code>internal/manager/rbac.go</code></a>, and the
              end-to-end tests check it with <code>kubectl auth can-i</code>: the operator cannot create, patch or delete
              workloads or Pods, cannot read Secrets and cannot create bindings.
            </p>
            <p>
              The pod runs as a non-root user with a read-only root filesystem, no capabilities,{' '}
              <code>RuntimeDefault</code> seccomp and no host access, so it passes the <code>restricted</code> Pod
              Security Standard.
            </p>
            <Notice label="Note">
              A clean result does not mean a cluster is secure. ClusterSentinel assesses configuration only. Use it
              alongside image scanners, runtime detection and admission control.
            </Notice>
          </section>

          <section id="resources">
            <h2>Resource usage</h2>
            <Table
              head={['What', 'Value']}
              rows={[
                ['Requests / limits', '25m CPU, 64Mi / 200m CPU, 128Mi'],
                ['Measured on kind (about 15 Pods)', '32 MB resident, 9 MB Go heap'],
                ['Image', 'about 52 MB unpacked, 17 MB compressed'],
                ['Disk used by the pod', 'none'],
                ['API server load', 'one list and watch per resource type; everything else is read from the cache. QPS 10, burst 20.'],
              ]}
            />
            <p>
              Memory grows with the number of objects in the cluster. Measurements on a large cluster are still to
              come; clusters with thousands of Pods will probably need a 256Mi limit. The Go memory limit is set to
              90% of the container limit automatically.
            </p>
          </section>

          <section id="limitations">
            <h2>Limitations</h2>
            <ul>
              <li>Pre-alpha: results are only logged; findings, the CLI, notifications and the Helm chart do not exist yet.</li>
              <li><code>SecurityPolicy</code> objects are not read yet: the operator-wide profile applies to every namespace.</li>
              <li>Tested on Kubernetes 1.31 to 1.34 (kind, end to end) and 1.37 (envtest). Not yet tested on managed clusters such as EKS, GKE or AKS.</li>
              <li>Pod changes that do not bump <code>metadata.generation</code> are picked up by the next rescan.</li>
            </ul>
          </section>

          <section id="development">
            <h2>Development</h2>
            <Table head={['Command', 'What it does']} rows={DEV.map(([c, d]) => [<code key={c}>{c}</code>, d])} />
            <p>Issues and pull requests are welcome on <a href={REPO}>GitHub</a>.</p>
          </section>
        </article>
      </div>
    </Layout>
  )
}
