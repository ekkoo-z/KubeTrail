---
name: resource-hijack-dos
description: Analyze cryptomining, resource hijack, GPU/CPU abuse, quota gaps, autoscaler abuse, and Kubernetes denial-of-service surfaces.
---

# Resource Hijack And DoS

Use this skill when facts mention resource requests/limits, quotas, LimitRanges, HPA/VPA, cluster autoscaler, GPU nodes, DaemonSets, Jobs, CronJobs, mining indicators, high CPU, image pull behavior, or object-count stress.

Scope boundary:

- Owns availability and resource-cost impact.
- Use `workload-controller-persistence` for repeated execution mechanics.
- Use `pod-escape-surface` for privileged/host escape impact.
- Use `image-registry-supply-chain` for malicious miner image provenance.

High-value evidence:

- No ResourceQuota/LimitRange in namespaces where workload creation is allowed.
- Ability to create DaemonSets, Jobs, CronJobs, or high-replica Deployments.
- GPU/CPU-intensive workloads, ML namespaces, Kubeflow/TensorFlow jobs, mining process/image/domain indicators.
- HPA/VPA/cluster autoscaler settings that can amplify cost or node count.
- Image pull loops, oversized images, unbounded ephemeral storage, memory limit greater than request, no CPU/memory limits.

Finding rules:

- Confirmed high: workload creation permission plus missing quotas/limits and broad controller capability, or observed miner/resource hijack indicators.
- Medium: quotas absent in sensitive namespace or GPU/ML workloads exposed but creation path unknown.
- Low: minor resource hygiene gap without creation permission or observed abuse.
- Unknown: resource policy facts missing.

Useful templates:

- `resource-hijack-dos-review`
- `controller-persistence-review`

Side-effecting templates (explicit authorization required):

- `pod-create-job`

Output notes:

- Separate cost/resource hijack from data compromise.
- Flag cryptomining indicators only when image/process/domain/resource evidence exists.
- Include safe validation only; do not propose destructive load tests unless explicitly requested for full-mode validation.
