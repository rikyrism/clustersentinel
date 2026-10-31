import { useState } from 'react'
import rules from '../data/rules.json'
import { Severity } from './ui.jsx'

// Real output of the operator for DEPLOYMENT with the recommended profile, captured on kind.
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
NAME                                       SEVERITY   RULE               KIND         RESOURCE   STATE
deployment-api-cs-container-001-126beb6f   CRITICAL   CS-CONTAINER-001   Deployment   api        Open
deployment-api-cs-container-002-1726c4ca   HIGH       CS-CONTAINER-002   Deployment   api        Open
deployment-api-cs-container-003-3db5b687   MEDIUM     CS-CONTAINER-003   Deployment   api        Open
deployment-api-cs-container-004-7b32104d   LOW        CS-CONTAINER-004   Deployment   api        Open
deployment-api-cs-container-005-fb550622   LOW        CS-CONTAINER-005   Deployment   api        Open
deployment-api-cs-container-007-5dfbcf4d   LOW        CS-CONTAINER-007   Deployment   api        Open
deployment-api-cs-image-001-344e7fa9       MEDIUM     CS-IMAGE-001       Deployment   api        Open
deployment-api-cs-sa-001-98a6ecad          LOW        CS-SA-001          Deployment   api        Open`

const YAML = `apiVersion: security.clustersentinel.io/v1alpha1
kind: SecurityFinding
metadata:
  name: deployment-api-cs-container-001-126beb6f
  namespace: shop
  labels:
    security.clustersentinel.io/rule-id: CS-CONTAINER-001
    security.clustersentinel.io/severity: CRITICAL
    security.clustersentinel.io/state: Open
  ownerReferences:            # deleted with the Deployment
    - apiVersion: apps/v1
      kind: Deployment
      name: api
spec:
  ruleID: CS-CONTAINER-001
  severity: CRITICAL
  title: Privileged container
  resource: {kind: Deployment, namespace: shop, name: api, container: api}
  evidence: spec.template.spec.containers[0].securityContext.privileged is true
  recommendation: Remove securityContext.privileged, or set it to false. Grant only
    the specific capabilities the container needs.
  documentationURL: https://clustersentinel.web.id/docs/#cs-container-001
status:
  state: Open
  firstDetectedAt: "2026-10-31T00:39:18Z"
  lastDetectedAt: "2026-10-31T00:39:18Z"`

const TABS = [
  ['results', 'Findings'],
  ['kubectl', 'kubectl get'],
  ['yaml', 'One finding'],
  ['log', 'Operator log'],
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
        {tab === 'kubectl' && (
          <div role="tabpanel">
            <p className="hint">Each result is a <code>SecurityFinding</code> in the workload&apos;s namespace.</p>
            <pre className="plain"><code>{KUBECTL}</code></pre>
          </div>
        )}
        {tab === 'yaml' && (
          <div role="tabpanel">
            <p className="hint">One of them, shortened. Fix the Deployment and its state turns <code>Resolved</code>.</p>
            <pre className="plain"><code>{YAML}</code></pre>
          </div>
        )}
        {tab === 'log' && (
          <div role="tabpanel">
            <p className="hint">Changes are also logged once, for your log stack. Timestamp and reconcile fields left out.</p>
            <pre className="plain"><code>{LOG}</code></pre>
          </div>
        )}
      </div>
    </div>
  )
}
