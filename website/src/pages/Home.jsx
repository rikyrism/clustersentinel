import Example from '../components/Example.jsx'
import Layout from '../components/Layout.jsx'
import UseCases from '../components/UseCases.jsx'
import { Backdrop, BlockHead, Notice, Progress, Severity, Shell } from '../components/ui.jsx'
import rules from '../data/rules.json'
import { PHASES, PHASES_DONE } from '../data/site.js'

const WHY = [
  ['Read-only', 'It cannot change your workloads',
    <>Only <code>get</code>, <code>list</code> and <code>watch</code> on what it audits. No access to Secrets at all. Fixes are suggestions for you to review.</>],
  ['Lightweight', 'One pod, no agents, no database',
    'Event-driven from a trimmed cache. No DaemonSet, no host access, no image scanning. Findings are stored as Kubernetes resources.'],
  ['Actionable', 'Every result says what and where',
    'A rule ID, a severity, the exact field that failed and a recommendation. One result per workload and container, never one per replica.'],
]

const STATS = [
  ['Memory', '32 MB', 'resident, 9 MB Go heap'],
  ['Requests', '25m / 64Mi', 'CPU / memory, limits 200m / 128Mi'],
  ['Disk', '0 B', 'read-only root filesystem, no volumes'],
  ['Image', '~17 MB', 'compressed pull, amd64 and arm64'],
]

const FLOW = [
  ['01 · Watch', 'Trimmed informer cache',
    'Workloads, Pods, RBAC and namespaces. Excluded namespaces are filtered by the API server; replica Pods keep only metadata.'],
  ['02 · Evaluate', 'Templates, not replicas',
    'A Deployment with 50 replicas is analyzed once, from its pod template, only when its spec changes.'],
  ['03 · Record', 'Only when something changed',
    'Each result is fingerprinted. An unchanged result causes no API write, also after a restart.'],
]

const PLATFORMS = ['Amazon EKS', 'Google GKE', 'Azure AKS', 'DigitalOcean', 'k3s', 'On-premises', 'kind']

// Alternating depths so neighbouring cards drift apart a little while scrolling.
const DEPTHS = [36, -18, 54, 0]
const depth = (i) => ({ '--d': DEPTHS[i % DEPTHS.length] })

const DOES = [
  'Container security context, with pod-level inheritance',
  'Host network, PID and IPC namespaces',
  <>Image tags: <code>latest</code> and untagged images</>,
  'ServiceAccount tokens and the default ServiceAccount',
  'Wildcard, sensitive and cluster-admin RBAC',
  'Namespaces with Pods but no NetworkPolicy',
]

const DOES_NOT = [
  'Change, patch or delete anything you run',
  'Read Secrets or environment variable values',
  'Scan images for CVEs (use Trivy or Grype)',
  'Detect runtime threats (use Falco or Tetragon)',
  'Enforce policies at admission (use Kyverno or Gatekeeper)',
  'Prove that network traffic is restricted',
]

function HeroVisual() {
  return (
    <div className="hero-visual" aria-hidden="true">
      <div className="float f1" style={{ '--d': -70 }}>
        <div className="card-top"><span className="dot" />Deployment shop/api<span className="count">8</span></div>
        <div className="mini"><Severity level="CRITICAL" /><span>Privileged container</span></div>
        <div className="mini"><Severity level="HIGH" /><span>Privilege escalation allowed</span></div>
        <div className="mini"><Severity level="MEDIUM" /><span>Image uses the latest tag</span></div>
        <div className="mini faded"><Severity level="LOW" /><span>Missing seccomp profile</span></div>
      </div>
      <div className="float f2" style={{ '--d': 50 }}>
        <span className="label">RBAC</span>
        <div className="verbs"><b>get</b><b>list</b><b>watch</b></div>
        <p>No write access to your workloads, no Secrets.</p>
      </div>
      <div className="float f3" style={{ '--d': -140 }}>
        <span className="label">Memory</span>
        <data value="32">32 MB</data>
      </div>
      <div className="float f4" style={{ '--d': 110 }}>
        <span className="label">Runs on</span>
        <p>EKS · GKE · AKS · k3s</p>
      </div>
    </div>
  )
}

export default function Home() {
  const next = PHASES.find((p) => p.state === 'next')
  return (
    <Layout current="home">
      <div className="hero home" data-parallax>
        <Backdrop />
        <div className="container hero-grid">
          <div className="hero-copy depth" style={{ '--d': 60 }}>
            <span className="pill"><b>v0.1 in progress</b> Read-only Kubernetes security posture operator</span>
            <h1>Know what is insecure in your cluster, <em>without</em> running a security platform.</h1>
            <p className="lede">
              ClusterSentinel is one small pod that watches your workloads and RBAC, checks them against 18 rules
              and tells you what to fix and how. It never changes anything in your cluster.
            </p>
            <div className="actions">
              <a className="btn primary" href="#install">Install on your cluster</a>
              <a className="btn" href="#use-cases">Real use cases</a>
            </div>
          </div>
          <HeroVisual />
        </div>
        <div className="container">
          <Notice label="Pre-alpha">
            Phase {PHASES_DONE} of {PHASES.length}. All 18 rules run and every issue is a <code>SecurityFinding</code>{' '}
            you can read with kubectl. Policies per namespace, the CLI and alerts come next. See the{' '}
            <a href="/roadmap/">roadmap</a>.
          </Notice>
        </div>
      </div>

      <div className="marquee" data-parallax aria-label="Supported platforms">
        <div className="marquee-row">
          {[...PLATFORMS, ...PLATFORMS].map((p, i) => <span key={i}>{p}</span>)}
        </div>
      </div>

      <section className="block" id="use-cases">
        <div className="container">
          <BlockHead label="Use cases" title="Built for clusters that run real traffic.">
            Four situations it is designed for. Each one says what works today and what arrives in a later phase.
          </BlockHead>
          <UseCases />
        </div>
      </section>

      <section className="block tinted" id="example" data-parallax>
        <Backdrop />
        <div className="container">
          <BlockHead label="Example" title="One Deployment in, eight findings out.">
            A single privileged container with a <code>latest</code> image, checked with the default profile. This is
            the real output of the rule engine: each result names the rule, the container and the exact field.
          </BlockHead>
          <Example />
        </div>
      </section>

      <div className="band" data-parallax aria-hidden="true">
        <div className="band-row">get · list · watch · get · list · watch · get · list · watch</div>
        <div className="band-row alt">never create · never update · never delete · never create</div>
      </div>

      <section className="block" data-parallax>
        <div className="container">
          <BlockHead label="Why" title="Small, predictable, and honest about what it does." />
          <div className="cards reveal">
            {WHY.map(([label, title, text], i) => (
              <div className="depth" style={depth(i)} key={label}>
                <div className="card">
                  <span className="label">{label}</span>
                  <h3>{title}</h3>
                  <p>{text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="block" data-parallax>
        <span className="watermark depth" style={{ '--d': 180 }} aria-hidden="true">32MB</span>
        <div className="container">
          <BlockHead label="Footprint" title="Measured, not promised.">
            Numbers from a kind test cluster with all controllers running. Large clusters will use more memory; that is
            still to be measured.
          </BlockHead>
          <div className="stats reveal">
            {STATS.map(([label, value, note], i) => (
              <div className="depth" style={depth(i + 1)} key={label}>
                <div className="stat">
                  <span className="label">{label}</span>
                  <data value={value}>{value}</data>
                  <p>{note}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="block" data-parallax>
        <span className="watermark right depth" style={{ '--d': 220 }} aria-hidden="true">18</span>
        <div className="container">
          <BlockHead label="Rules" title={`${rules.length} built-in rules.`}>
            Default severities are deliberately moderate: missing hardening is not the same as an exploitable
            vulnerability. Profiles are nested: basic ⊂ recommended ⊂ strict.
          </BlockHead>
          <div className="table-wrap reveal">
            <table>
              <thead>
                <tr><th>ID</th><th>Rule</th><th>Default</th><th className="hide-sm">Profiles</th></tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td className="id"><a href={`/docs/#${r.id.toLowerCase()}`}>{r.id}</a></td>
                    <td>{r.name}</td>
                    <td><Severity level={r.severity} /></td>
                    <td className="hide-sm">{r.profiles.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="block" data-parallax>
        <div className="container">
          <BlockHead label="How it works" title="Watch, evaluate, record." />
          <div className="flow reveal">
            {FLOW.map(([label, title, text], i) => (
              <div className="depth" style={depth(i)} key={label}>
                <div className="step">
                  <span className="label">{label}</span>
                  <h3>{title}</h3>
                  <p>{text}</p>
                </div>
              </div>
            ))}
            <div className="depth" style={depth(3)}>
              <div className="step">
                <span className="label">04 · Report</span>
                <h3>Findings and a cluster report</h3>
                <p><code>kubectl get securityfindings -A</code> today; a CLI and Discord, Slack or webhook alerts later.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="block">
        <div className="container two">
          <div>
            <BlockHead label="It does" title="Configuration checks" />
            <ul className="checks reveal">{DOES.map((d, i) => <li key={i}>{d}</li>)}</ul>
          </div>
          <div>
            <BlockHead label="It does not" title="Replace other tools" />
            <ul className="checks no reveal">{DOES_NOT.map((d) => <li key={d}>{d}</li>)}</ul>
          </div>
        </div>
      </section>

      <section className="block tinted" id="install" data-parallax>
        <Backdrop />
        <div className="container">
          <BlockHead label="Install" title="Run it on the cluster you already have.">
            EKS, GKE, AKS, k3s or on-premises: it only needs the Kubernetes API. Until the Helm chart in Phase 7, you
            build the image, push it to your registry and apply one YAML file.
          </BlockHead>
          <div className="install reveal">
            <Shell
              title="your cluster"
              lines={[
                ['export IMG=<registry>/clustersentinel:dev', 'ECR, Artifact Registry, ACR, GHCR…'],
                ['make docker-buildx IMG=$IMG', 'amd64 + arm64, pushed'],
                ['make build-installer IMG=$IMG', 'writes dist/install.yaml, review it'],
                ['kubectl config current-context', 'the cluster you mean?'],
                ['kubectl apply -f dist/install.yaml'],
              ]}
            />
            <p className="install-note">
              Full steps, private registries and production settings are in the{' '}
              <a href="/docs/#quick-start">install guide</a>. Just trying it? <a href="/docs/#local">Run it on kind</a>.
            </p>
          </div>
        </div>
      </section>

      <section className="block cta" data-parallax>
        <span className="watermark depth" style={{ '--d': 200 }} aria-hidden="true">{PHASES_DONE}/{PHASES.length}</span>
        <div className="container">
          <BlockHead label="Roadmap" title={`${PHASES_DONE} of ${PHASES.length} phases done.`}>
            Next: {next.title.toLowerCase()}. {next.summary}
          </BlockHead>
          <Progress />
          <div className="actions"><a className="btn" href="/roadmap/">See the full roadmap</a></div>
        </div>
      </section>
    </Layout>
  )
}
