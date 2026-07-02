---
name: admission-policy-governance
description: Analyze Pod Security Admission, validating/mutating webhooks, policy engines, image policy, and whether dangerous specs can be admitted.
---

# Admission Policy Governance

Use this skill when facts mention Pod Security Admission, namespace labels, Gatekeeper, Kyverno, validating or mutating webhooks, image policy, allowed registries, signature policies, ResourceQuota, or LimitRange.

Scope boundary:

- Owns whether risky API requests would be admitted after authorization.
- Use `k8s-rbac-analysis` for whether an identity can submit the request.
- Use `pod-escape-surface` for risks in already-running pods.
- Use `image-registry-supply-chain` for image provenance and signature details.

High-value evidence:

- Namespace labels for `pod-security.kubernetes.io/enforce`, `audit`, `warn` and levels privileged/baseline/restricted.
- Webhook configuration, failurePolicy, namespace/object selectors, sideEffects, timeout, match policy, excluded namespaces.
- Gatekeeper/Kyverno policies blocking privileged, hostPath, hostPID, hostNetwork, hostIPC, hostPort, unsafe capabilities, mutable images, untrusted registries.
- Missing or permissive admission in sensitive namespaces.
- Quotas and limits for CPU/GPU/memory, object counts, and ephemeral storage.

Finding rules:

- Confirmed high: identity can create/patch workloads and admission does not block privileged/hostPath/hostNetwork or untrusted images in target namespace.
- Medium: admission exists but has bypass selectors, ignore/fail-open behavior, or privileged namespace exclusions.
- Low: warn/audit-only policies or missing policy with no create/update permission evidence.
- Unknown: authorization known but admission facts missing.

Useful templates:

- `admission-policy-review`
- `admission-persistence-review`
- `image-supply-chain-review`

Side-effecting templates (explicit authorization required):

- `pod-privileged`
- `pod-hostpath`

Output notes:

- Separate authorization from admission. A dangerous request needs both permission and admission.
- Name the target namespace and policy mode.
- Highlight fail-open webhooks and broad namespace exclusions.
