---
name: cloud-metadata-analysis
description: Analyze cloud metadata reachability and cloud workload identity exposure from KubeTrail results.
---

# Cloud Metadata And Identity

Use this skill when facts mention cloud metadata endpoints, cloud provider identity, projected workload identity, IMDS reachability, or provider-specific credential exchange.

Scope boundary:

- Owns cluster-to-cloud identity and metadata exposure.
- Do not score generic Kubernetes Secret, kubeconfig, image pull secret, or filesystem credential material here; use `serviceaccount-secret-material`.
- Do not score Kubernetes API authorization here; use `k8s-rbac-analysis`.
- Do not treat metadata reachability alone as cloud account compromise.

High-value evidence:

- Metadata endpoint `169.254.169.254`, provider aliases, hop-limit or token requirement results.
- AWS IMDSv1/IMDSv2 status, IAM role name, security credentials path, EKS IRSA env and projected token hints, EKS Pod Identity agent hints.
- GCP metadata headers, service account email, access token availability, Workload Identity projected token hints.
- Azure IMDS and Azure Workload Identity env such as tenant/client/federated token file hints.
- Alibaba, Tencent, Huawei, OCI metadata reachability or temporary credential indicators.
- Egress filtering evidence that blocks metadata from workload pods.

Finding rules:

- Confirmed high: provider-issued credential material, role name plus token/identity document, or sensitive ref tied to cloud identity.
- Medium: metadata endpoint reachable and provider identified, but no credential material returned.
- Low: workload identity env or projected token hints exist but no token material or exchange result is present.
- Unknown: collector was denied, timed out, or only local env hints exist without metadata/API evidence.

Useful templates:

- `cloud-metadata-verify`
- `cloud-identity-verify`

Output notes:

- Name the provider and identity mechanism when known.
- State whether evidence proves reachability, identity discovery, credential access, or only configuration hints.
- Include what extra collection is needed: full-mode metadata probe, egress check, workload token projection facts, or cloud STS/identity read-only verification.
