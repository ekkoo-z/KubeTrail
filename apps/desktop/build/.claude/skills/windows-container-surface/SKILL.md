---
name: windows-container-surface
description: Analyze Windows node and Windows container attack surfaces, including Windows Server container boundary risk and node credential spread.
---

# Windows Container Surface

Use this skill only when facts mention Windows nodes, Windows containers, HostProcess pods, Windows Server containers, Hyper-V isolation, Windows kubelet, or Windows-specific runtime details.

Scope boundary:

- Owns Windows-specific container and node surfaces.
- Use `pod-escape-surface` for generic Linux pod security findings.
- Use `kubelet-runtime-etcd-bypass` for kubelet/runtime API access independent of OS.
- Use `serviceaccount-secret-material` for tokens and kubeconfigs found on Windows nodes or containers.

High-value evidence:

- Windows Server containers without Hyper-V isolation, HostProcess pods, privileged-like host access, host filesystem mounts.
- Windows node OS/version, container runtime, patch level, kubelet config, node credentials.
- Workloads running common exposed Windows apps or web servers with known vulnerable versions.
- Node credential paths that can be abused after host access.
- Mixed Linux/Windows cluster movement paths and scheduling constraints.

Finding rules:

- Confirmed high: Windows container host access plus node credential or kubelet/client material.
- Medium: Windows Server container isolation risk with exposed workload or high-privilege ServiceAccount.
- Low: Windows node present with no risky workload or credential evidence.
- Unknown: OS detected but runtime/isolation details missing.

Useful templates:

- `windows-container-review`
- `serviceaccount-token-api-verify`
- `kubelet-api-verify`

Output notes:

- Activate only for Windows evidence; do not include in Linux-only findings.
- Avoid assuming Windows Server containers are a hard security boundary.
- State whether Hyper-V isolation, HostProcess, or node credential evidence is known.
