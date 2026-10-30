# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Kubebuilder project (Go 1.26, controller-runtime v0.25, Kubernetes API 1.37).
- CRDs `SecurityPolicy`, `SecurityFinding` and `SecurityReport` (`security.clustersentinel.io/v1alpha1`) with schema validation and defaults.
- Rule catalog for the 18 MVP rules (metadata, default severities, profiles); detection logic is not implemented yet.
- Operator configuration file with validation, including notification channels of type `discord`, `slack` and `webhook`.
- Manager with JSON logging, leader election, health probes, Prometheus metrics endpoint, a trimmed informer cache and a Go memory limit derived from the container limit.
- Least-privilege ClusterRole (read-only on audited resources, no Secret access).
- Hardened deployment manifests, Dockerfile with version metadata, kind development targets isolated from `~/.kube/config`, and an e2e suite.
