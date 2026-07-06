---
name: observability-defense-evasion
description: Analyze audit, logging, runtime detection, event visibility, and defense evasion surfaces in KubeTrail results.
---

# Observability And Defense Evasion

Use this skill when facts mention audit logging, events, log access/deletion, runtime sensors, Falco, Tetragon, eBPF agents, SIEM forwarding, admission audit mode, kubelet/etcd bypass, process cleanup, or suspicious stealth behavior.

Scope boundary:

- Owns whether activity would be visible, hidden, or easy to erase.
- Use `kubelet-runtime-etcd-bypass` for the bypass primitive itself.
- Use `workload-controller-persistence` for persistence objects.
- Use `resource-hijack-dos` for mining or noisy resource consumption impact.

High-value evidence:

- Kubernetes API audit enabled/disabled, audit policy scope, log sink, retention, and sensitive request/response redaction.
- Event/log delete permissions, pods/log access, namespace event churn.
- Runtime detection agents present or absent: Falco, Tetragon, Tracee, Defender, GuardDuty EKS, Cilium Hubble, Datadog, Sysdig.
- Kubelet or etcd direct access that bypasses admission/audit.
- Cleanup indicators: history removal, deleted payloads, hidden processes, rootkit hints, non-standard miner ports, Cloudflare/Tor/tunnel C2 hints.

Finding rules:

- Confirmed high: high-impact action path bypasses audit or identity can delete logs/events plus runtime detection absent.
- Medium: audit/runtime visibility unknown for high-risk findings.
- Low: monitoring gaps without a paired attack path.
- Unknown: collector lacks audit/logging/security-agent facts.

Useful templates:

- `observability-evasion-review`
- `kubelet-api-verify`
- `etcd-access-verify`

Output notes:

- Tie visibility gaps to specific attack paths.
- Do not overstate stealth from missing data; mark unknown when collectors did not observe logging posture.
- Include defensive fix direction: enable audit, centralize logs, restrict delete, deploy runtime detection, monitor component APIs.
