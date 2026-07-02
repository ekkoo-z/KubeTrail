---
name: public-workload-rce-surface
description: Analyze internet-facing or internally reachable workload compromise posture and the post-compromise cluster blast radius.
---

# Public Workload RCE Surface

Use this skill when facts mention exposed application workloads, images with vulnerable versions, public services, ingress hosts, known CVEs, process/env evidence, reverse shell indicators, or workload reachability.

Scope boundary:

- Owns "if this workload is compromised, what can it reach or steal" analysis.
- Use `exposed-management-interfaces` for admin dashboards and management tools.
- Use `service-ingress-exposure` for pure Service/Ingress exposure mechanics.
- Use `image-registry-supply-chain` for image provenance and malicious image risk.

High-value evidence:

- Public-facing workloads with known vulnerable product/version, risky app paths, default creds, or no auth.
- Container env and mounted token facts that become available after RCE.
- Egress to API server, metadata endpoint, kubelet, internal services, databases, or internet C2.
- NetworkPolicy, ServiceAccount, and namespace context for post-compromise movement.
- Runtime observations: shell process, downloader, miner, unusual DNS, outbound callback, cron persistence.

Finding rules:

- Confirmed high: vulnerable exposed workload plus token/secret/cloud material or high-risk egress path.
- Medium: exposed workload with vulnerable/unknown version and meaningful internal reachability.
- Low: exposed workload with restricted token, restricted egress, and no known vulnerable version.
- Unknown: exposure exists but image/version/env/network facts are missing.

Useful templates:

- `workload-rce-posture-review`
- `serviceaccount-token-api-verify`
- `cloud-metadata-verify`
- `network-lateral-movement-review`

Output notes:

- Do not provide exploit payloads for product CVEs from this skill.
- Explain blast radius in terms of available facts: token, env, files, network, namespace, RBAC.
- State which collector facts are needed to move from posture to confirmed exploitation risk.
