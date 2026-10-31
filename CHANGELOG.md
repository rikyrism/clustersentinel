# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Kubebuilder project (Go 1.26, controller-runtime v0.25, Kubernetes API 1.37).
- CRDs `SecurityPolicy`, `SecurityFinding` and `SecurityReport` (`security.clustersentinel.io/v1alpha1`) with schema validation and defaults.
- Rule catalog for the 18 MVP rules (metadata, default severities, profiles, description and recommendation).
- Detection logic for all 18 rules: container security context (with pod-level inheritance, init and ephemeral containers, Windows pods), host namespaces, image tags, ServiceAccount tokens, wildcard, cluster-admin and sensitive RBAC, and namespaces without a NetworkPolicy.
- Controllers for Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, Pods, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings and Namespaces. Templates are analyzed instead of replicas; Pods of unknown controllers are grouped per controller. Changed results are also logged.
- Periodic rescan from the cache (`scanner.scanInterval`, jittered).
- Results are written as `SecurityFinding` resources: one per resource, rule and container, with a deterministic name, labels for rule, severity, state, resource and scan unit, and an owner reference so Kubernetes deletes them with their object. Unchanged results cause no API writes, also after a restart.
- Findings turn `Resolved` when the issue disappears or the resource leaves the scan scope, and reopen if it comes back. `lastDetectedAt` is refreshed at most once per rescan interval.
- At start, the leader resolves open findings of disabled rules and unscanned namespaces. Every minute it deletes Resolved findings older than `scanner.resolvedRetention` and updates the `SecurityReport` named `cluster`, only when it changed. Findings created by hand are left alone.
- Findings about ClusterRoles and ClusterRoleBindings are kept in the operator's namespace, and the missing NetworkPolicy finding in the namespace it is about.
- Website with landing page, documentation and roadmap (React + Vite, `website/`), published to https://clustersentinel.web.id by a GitHub Pages workflow. Its rule data is generated from the rule catalog (`make site-data`) and checked in CI.
- Finding documentation links point to the rule's section on the website.
- Operator configuration file with validation, including notification channels of type `discord`, `slack` and `webhook`.
- Manager with JSON logging, leader election, health probes, Prometheus metrics endpoint, a trimmed informer cache and a Go memory limit derived from the container limit.
- `namespaces.exclude` is applied as a server-side field selector; ReplicaSets of Deployments and Jobs of CronJobs are cached without their pod template; controllers for disabled rules are not started.
- Least-privilege ClusterRole (read-only on audited resources, no Secret access).
- Hardened deployment manifests, Dockerfile with version metadata, kind development targets isolated from `~/.kube/config`, and an e2e suite.
- `KIND_NODE_IMAGE` option for `make test-e2e` to test other Kubernetes versions; verified on 1.31 to 1.34.

### Security
- Pin kind (v0.30.0, checksum verified) in the e2e workflow and the logcheck lint plugin (v0.11.0).
- CI fails when `go.mod`/`go.sum` are not tidy or generated code is stale, instead of fixing it silently.
- Remove the privileged devcontainer that installed unpinned tools.
- The scaffolded `*-admin-role` ClusterRoles list their verbs instead of granting `*`.
- The operator can read ReplicaSets (`get`, `list`, `watch`), to analyze those not owned by a Deployment. It still has no write access to any workload.
