import { useState } from 'react'
import rules from '../data/rules.json'
import { Severity } from './ui.jsx'

// Real output: the rule engine run on DEPLOYMENT with the recommended profile.
const DEPLOYMENT = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/shop-api:latest
          securityContext:
            privileged: true`

const T = 'spec.template.spec'
const C = `${T}.containers[0]`
const RESULTS = [
  ['CS-CONTAINER-001', 'api', `${C}.securityContext.privileged is true`],
  ['CS-CONTAINER-002', 'api', `${C}.securityContext.allowPrivilegeEscalation is not set (defaults to true)`],
  ['CS-CONTAINER-003', 'api', `neither runAsNonRoot: true nor a non-zero runAsUser is set for ${C} or in ${T}.securityContext`],
  ['CS-IMAGE-001', 'api', `${C}.image is "ghcr.io/acme/shop-api:latest"`],
  ['CS-CONTAINER-004', 'api', `${C}.securityContext.readOnlyRootFilesystem is not true`],
  ['CS-CONTAINER-005', 'api', `${C}.securityContext.capabilities.drop does not include ALL`],
  ['CS-CONTAINER-007', 'api', `no seccompProfile is set for ${C} or in ${T}.securityContext (Unconfined unless the kubelet enables RuntimeDefault)`],
  ['CS-SA-001', '', `${T}.automountServiceAccountToken is not set and ServiceAccount "default" does not disable it (defaults to true)`],
]
const BY_ID = Object.fromEntries(rules.map((r) => [r.id, r]))

const LOG = `{
  "level": "info",
  "msg": "Analysis result changed",
  "controller": "deployment",
  "resourceKind": "Deployment",
  "resourceNamespace": "shop",
  "resourceName": "api",
  "violations": 8,
  "rules": [
    "CS-CONTAINER-001/api", "CS-CONTAINER-002/api",
    "CS-CONTAINER-003/api", "CS-CONTAINER-004/api",
    "CS-CONTAINER-005/api", "CS-CONTAINER-007/api",
    "CS-IMAGE-001/api", "CS-SA-001"
  ]
}`

const KUBECTL = `$ kubectl get securityfindings -n shop
NAME                               SEVERITY   RULE               KIND         RESOURCE   STATE
deployment-api-cs-container-001-…  CRITICAL   CS-CONTAINER-001   Deployment   api        Open
deployment-api-cs-container-002-…  HIGH       CS-CONTAINER-002   Deployment   api        Open
deployment-api-cs-container-003-…  MEDIUM     CS-CONTAINER-003   Deployment   api        Open
deployment-api-cs-image-001-…      MEDIUM     CS-IMAGE-001       Deployment   api        Open
deployment-api-cs-container-004-…  LOW        CS-CONTAINER-004   Deployment   api        Open
…`

const TABS = [
  ['results', 'Findings'],
  ['log', 'Operator log'],
  ['kubectl', 'kubectl · Phase 3'],
]

export default function Example() {
  const [tab, setTab] = useState('results')
  return (
    <div className="example reveal">
      <div className="window input">
        <div className="window-bar" aria-hidden="true"><i /><i /><i /><span>deployment.yaml</span></div>
        <pre><code>{DEPLOYMENT}</code></pre>
      </div>

      <div className="output">
        <div className="tabs" role="tablist" aria-label="Example output">
          {TABS.map(([key, label]) => (
            <button key={key} role="tab" type="button" aria-selected={tab === key} onClick={() => setTab(key)}>
              {label}
            </button>
          ))}
        </div>

        {tab === 'results' && (
          <ul className="findings" role="tabpanel">
            {RESULTS.map(([id, container, evidence]) => (
              <li key={id}>
                <div className="row">
                  <Severity level={BY_ID[id].severity} />
                  <a className="id" href={`/docs/#${id.toLowerCase()}`}>{id}</a>
                  <strong>{BY_ID[id].name}</strong>
                  {container && <span className="ctr">container {container}</span>}
                </div>
                <code className="evidence">{evidence}</code>
              </li>
            ))}
          </ul>
        )}
        {tab === 'log' && (
          <div role="tabpanel">
            <p className="hint">What the operator writes today, once per change. Timestamp and reconcile fields left out.</p>
            <pre className="plain"><code>{LOG}</code></pre>
          </div>
        )}
        {tab === 'kubectl' && (
          <div role="tabpanel">
            <p className="hint">Planned for Phase 3: each result becomes a <code>SecurityFinding</code>. Names are shortened.</p>
            <pre className="plain"><code>{KUBECTL}</code></pre>
          </div>
        )}
      </div>
    </div>
  )
}
