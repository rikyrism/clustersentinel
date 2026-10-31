// Facts shown on more than one page. Keep them in line with docs/implementation-plan.md.
export const REPO = 'https://github.com/rikyrism/clustersentinel'

export const PHASES = [
  {
    state: 'done',
    title: 'Bootstrap',
    summary: 'CRDs, manager, container image, kind workflow, RBAC contract.',
    items: [
      'SecurityPolicy, SecurityFinding and SecurityReport CRDs with schema validation',
      'Hardened Deployment that passes the restricted Pod Security Standard',
      'Least-privilege ClusterRole, verified with kubectl auth can-i',
      'Trimmed informer cache and a Go memory limit taken from the container limit',
    ],
    verified: 'envtest CRD tests on Kubernetes 1.31–1.37, e2e on kind 1.31–1.34, amd64 and arm64 images.',
  },
  {
    state: 'done',
    title: 'Workload scanning',
    summary: 'Controllers and detection logic for all 18 rules. Results are logged.',
    items: [
      'Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs analyzed from their pod template',
      'Pods of unknown controllers grouped per controller, so 50 replicas give one result',
      'Roles, ClusterRoles, bindings and NetworkPolicy presence',
      'Status-only updates ignored, excluded namespaces filtered by the API server, jittered rescan',
    ],
    verified: 'unit tests for every rule, controller tests against a real API server, e2e detection on kind. 32 MB RSS on kind.',
  },
  {
    state: 'next',
    title: 'Findings',
    summary: 'Turn results into SecurityFinding resources that live and die with the workload.',
    items: [
      'Deterministic names from resource UID, rule and container: rescans update, never duplicate',
      'Findings move to Resolved on their own when the issue is fixed',
      'Owner references, so findings are deleted with their workload',
      'Retention for Resolved findings and one cluster SecurityReport',
    ],
  },
  {
    state: 'planned',
    title: 'Configuration',
    summary: 'SecurityPolicy per namespace.',
    items: [
      'Profiles and per-rule overrides per namespace',
      'Oldest policy wins when there are several',
      'Policy status reports whether it is active',
    ],
  },
  {
    state: 'planned',
    title: 'CLI',
    summary: 'A clustersentinel command for people and pipelines.',
    items: [
      'summary, findings, describe, report (table, JSON, YAML), rules, version',
      'fix: a YAML patch to review and apply yourself',
      'Optional CI gate with an exit code by severity',
    ],
  },
  {
    state: 'planned',
    title: 'Notifications and metrics',
    summary: 'Know when something new shows up.',
    items: [
      'Discord, Slack and generic webhook channels, several at once',
      'Deduplicated per finding, retried with backoff, first scan sent as one digest',
      'Prometheus metrics with low-cardinality labels',
    ],
  },
  {
    state: 'planned',
    title: 'Helm and release',
    summary: 'Install it like any other operator.',
    items: [
      'Helm chart with the same hardening and RBAC',
      'Multi-arch release images, dependency and image scanning in CI',
      'Full documentation and a security policy',
    ],
  },
]

export const PHASES_DONE = PHASES.filter((p) => p.state === 'done').length
