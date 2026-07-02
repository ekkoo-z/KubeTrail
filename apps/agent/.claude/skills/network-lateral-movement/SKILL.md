---
name: network-lateral-movement
description: Analyze east-west network movement, namespace isolation, egress to sensitive endpoints, DNS, and metadata/API reachability from compromised pods.
---

# Network Lateral Movement

Use this skill when facts mention NetworkPolicy, CNI, DNS, service reachability, pod-to-pod traffic, namespace isolation, egress, internal scanning, API server reachability, metadata reachability, or service mesh.

Scope boundary:

- Owns internal and outbound network paths from workloads.
- Use `service-ingress-exposure` for external entry points.
- Use `cloud-metadata-analysis` for cloud identity impact after metadata is reachable.
- Use `kubelet-runtime-etcd-bypass` for component API consequences after network reachability is shown.

High-value evidence:

- No default deny NetworkPolicy, default allow ingress/egress, CNI without NetworkPolicy enforcement.
- Egress from workload to API server, kubelet nodes, etcd, metadata, DNS, databases, service meshes, registries, or internet.
- Cross-namespace service access, headless services, service discovery, DNS wildcard egress.
- Service mesh mTLS absent or permissive authorization policy.
- Runtime scanning tools or commands, unusual DNS domains, high fan-out connections.

Finding rules:

- Confirmed high: compromised pod can reach API server/metadata/kubelet/etcd/internal sensitive services and has token or credential material.
- Medium: network allows broad east-west or egress but credential/material evidence is absent.
- Low: missing default deny with limited sensitive endpoints observed.
- Unknown: CNI or NetworkPolicy facts unavailable.

Useful templates:

- `network-lateral-movement-review`
- `cloud-metadata-verify`
- `kubelet-api-verify`

Output notes:

- Separate ingress, egress, and east-west findings.
- Explain whether the path is exploitable from the current pod, namespace, or any pod.
- Name the endpoint class: API server, metadata, kubelet, etcd, database, registry, internet.
