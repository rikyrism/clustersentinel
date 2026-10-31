import { Severity } from './ui.jsx'

// Real situations ClusterSentinel is built for. Each says what is planned on top of what works
// today, and the log visuals use the operator's real log format.

function Log({ lines }) {
  return (
    <pre className="uc-log"><code>{lines.join('\n')}</code></pre>
  )
}

const CASES = [
  {
    key: 'inherited',
    label: 'Inherited cluster',
    title: 'You took over an EKS cluster nobody fully understands.',
    text: (
      <>
        Install it once and the first scan lists every privileged container, every workload on the host network,
        every <code>latest</code> image and every subject bound to <code>cluster-admin</code>, across all
        namespaces, on its first scan. Nothing is changed while it looks.
      </>
    ),
    plans: ['Phase 3: browse results with kubectl get securityfindings'],
    visual: (
      <div className="uc-window">
        <div className="window-bar" aria-hidden="true"><i /><i /><i /><span>kubectl logs · first scan</span></div>
        <Log lines={[
          '{"msg":"Analysis result changed","resourceKind":"Deployment",',
          ' "resourceNamespace":"payments","resourceName":"worker",',
          ' "violations":6,"rules":["CS-CONTAINER-001/worker", …]}',
          '{"msg":"Analysis result changed","resourceKind":"DaemonSet",',
          ' "resourceNamespace":"monitoring","resourceName":"node-agent",',
          ' "violations":4,"rules":["CS-CONTAINER-008","CS-CONTAINER-009", …]}',
          '{"msg":"Analysis result changed","resourceKind":"ClusterRoleBinding",',
          ' "resourceName":"ci-deployer","violations":1,"rules":["CS-RBAC-002"]}',
        ]} />
      </div>
    ),
    chips: [['CRITICAL', 'privileged: true'], ['HIGH', 'cluster-admin → ci/deployer']],
  },
  {
    key: 'drift',
    label: 'Platform team',
    title: 'Forty teams deploy with Helm and Argo CD. You want to know when a chart gets worse.',
    text: (
      <>
        Results are fingerprinted, so the log only speaks when something changes: a new chart version that adds{' '}
        <code>privileged: true</code>, an image switched to <code>latest</code>, a Role that grows a wildcard. When
        the team fixes it, the result changes back to zero.
      </>
    ),
    plans: ['Phase 4: per-namespace policy', 'Phase 6: Slack, Discord or webhook alerts'],
    visual: (
      <div className="uc-timeline">
        <div className="uc-event">
          <span className="t">14:02</span>
          <div>
            <strong>helm upgrade checkout 2.3.0</strong>
            <p>violations 0 → 2</p>
            <div className="uc-tags"><Severity level="CRITICAL" /><code>CS-CONTAINER-001/app</code></div>
            <div className="uc-tags"><Severity level="MEDIUM" /><code>CS-IMAGE-001/app</code></div>
          </div>
        </div>
        <div className="uc-event ok">
          <span className="t">14:31</span>
          <div>
            <strong>helm upgrade checkout 2.3.1</strong>
            <p>violations 2 → 0</p>
          </div>
        </div>
        <div className="uc-event quiet">
          <span className="t">every 30m</span>
          <div>
            <strong>rescan from cache</strong>
            <p>nothing changed, nothing logged</p>
          </div>
        </div>
      </div>
    ),
    chips: [['MEDIUM', 'latest tag'], ['LOW', 'no seccomp']],
  },
  {
    key: 'audit',
    label: 'Security review',
    title: 'An auditor asks how your workloads are hardened. You need an answer, not a spreadsheet.',
    text: (
      <>
        The checks are based on the Kubernetes Pod Security Standards and RBAC good practice, and each result names the
        exact field. The <code>strict</code> profile adds default ServiceAccount use and namespaces without a
        NetworkPolicy. Read-only access means the security team can run it without change approval for workloads.
      </>
    ),
    plans: ['Phase 3: cluster SecurityReport', 'Phase 5: report as JSON or YAML'],
    visual: (
      <div className="uc-report">
        <div className="uc-report-head"><span className="label">SecurityReport · planned</span><strong>prod-eks</strong></div>
        <div className="uc-bars">
          {[['CRITICAL', 2, 8], ['HIGH', 9, 30], ['MEDIUM', 21, 64], ['LOW', 37, 100]].map(([sev, n, w]) => (
            <div key={sev} className="uc-bar">
              <Severity level={sev} />
              <span className="track"><i className={sev} style={{ width: `${w}%` }} /></span>
              <b>{n}</b>
            </div>
          ))}
        </div>
        <p className="uc-note">Illustrative numbers.</p>
      </div>
    ),
    chips: [['HIGH', 'wildcard verbs'], ['INFO', 'default ServiceAccount']],
  },
  {
    key: 'edge',
    label: 'Small clusters',
    title: 'k3s at the edge, a homelab, or a staging cluster where every megabyte counts.',
    text: (
      <>
        One pod, 25m CPU and 64Mi requested, about 32 MB in use on a test cluster. No DaemonSet, no database, no
        disk. The image is built for amd64 and arm64, so it runs on Graviton, Ampere and Raspberry Pi nodes alike.
      </>
    ),
    plans: ['Phase 7: Helm chart and release images'],
    visual: (
      <div className="uc-meters">
        {[['memory', '32 MB', 25, 'of 128Mi limit'], ['cpu request', '25m', 12, 'of 200m limit'], ['disk', '0 B', 0, 'read-only root filesystem']].map(([k, v, w, note]) => (
          <div key={k} className="uc-meter">
            <div className="row"><span className="label">{k}</span><b>{v}</b></div>
            <span className="track"><i style={{ width: `${Math.max(w, 1)}%` }} /></span>
            <p>{note}</p>
          </div>
        ))}
        <div className="uc-arch"><code>linux/amd64</code><code>linux/arm64</code></div>
      </div>
    ),
    chips: [[null, '1 pod'], [null, 'no agents']],
  },
]

export default function UseCases() {
  return (
    <div className="usecases">
      {CASES.map((c, i) => (
        <article key={c.key} className={`uc ${i % 2 ? 'flip' : ''}`} data-parallax>
          <div className="uc-copy reveal">
            <span className="label accent">{String(i + 1).padStart(2, '0')} · {c.label}</span>
            <h3>{c.title}</h3>
            <p>{c.text}</p>
            <span className="chip now">Works today</span>
            <ul className="uc-plan">
              {c.plans.map((t) => <li key={t}>{t}</li>)}
            </ul>
          </div>
          <div className="uc-visual" aria-hidden="true">
            <div className="uc-plate depth" style={{ '--d': 70 }} />
            <div className="uc-front depth" style={{ '--d': -30 }}>{c.visual}</div>
            {c.chips.map(([sev, text], j) => (
              <div key={text} className={`uc-chip depth c${j}`} style={{ '--d': j ? -150 : -100 }}>
                {sev && <Severity level={sev} />}<span>{text}</span>
              </div>
            ))}
          </div>
        </article>
      ))}
    </div>
  )
}
