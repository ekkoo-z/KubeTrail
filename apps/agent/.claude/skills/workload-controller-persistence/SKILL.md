---
name: workload-controller-persistence
description: Analyze Kubernetes workload controllers and objects that can provide persistence or repeated execution.
---

# Workload Controller Persistence

Use this skill when facts mention Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs, CronJobs, static pods, lifecycle hooks, sidecars, init containers, or controller-created workloads.

Scope boundary:

- Owns persistence through Kubernetes objects and workload lifecycle mechanics.
- Use `k8s-rbac-analysis` to decide whether the current identity can create or modify these objects.
- Use `pod-escape-surface` to score the danger of the PodSpec those controllers run.
- Use `observability-defense-evasion` for stealth/logging consequences.

High-value evidence:

- DaemonSet in `kube-system` or broad node coverage, suspicious names such as proxy-api, kube-controller, metrics, pause, system.
- CronJob/Job with downloader, shell, miner, reverse shell, cleanup, or credential sweep behavior.
- Mutating webhook or operator injecting sidecars/init containers.
- Static pod manifests or mirror pods not governed by normal controllers.
- Owner references, restartPolicy, replica counts, tolerations, node selectors, host mounts, privileged flags.

Finding rules:

- Confirmed high: controller creates high-privilege pods, spans nodes, runs in system namespace, or has suspicious image/process evidence.
- Medium: ability to create/update controllers plus missing admission controls.
- Low: benign controller persistence potential without dangerous PodSpec or permissions.
- Unknown: controller list exists but pod template or permissions are missing.

Useful templates:

- `controller-persistence-review`
- `static-pod-node-persistence-review`

Side-effecting templates (explicit authorization required):

- `workload-patch-sidecar-persistence`
- `serviceaccount-rbac-persistence`
- `pod-create-job`
- `pod-privileged`
- `pod-hostpath`

Output notes:

- Distinguish persistence potential from active malicious persistence.
- Include cleanup/rollback considerations for side-effecting validation.
- Flag conflicts with known real-world patterns: DaemonSet miners, kube-system impersonation, scheduled downloader jobs.
