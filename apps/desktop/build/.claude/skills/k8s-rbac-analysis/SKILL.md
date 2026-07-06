---
name: k8s-rbac-analysis
description: Analyze Kubernetes API authorization, RBAC grants, SSRR/SSAR output, and high-value API attack paths from KubeTrail results.
---

# Kubernetes RBAC Analysis

Use this skill when the user asks about permissions, privilege escalation, current ServiceAccount capability, or Kubernetes API attack paths.

Scope boundary:

- Owns Kubernetes API authorization only: verbs, resources, scopes, subresources, and review results.
- Do not analyze whether a PodSpec is dangerous; use `pod-escape-surface` or `admission-policy-governance`.
- Do not analyze material present in tokens/secrets; use `serviceaccount-secret-material`.
- Do not treat `nodes/proxy` as read-only; it belongs here as an authorization finding and may also feed `kubelet-runtime-etcd-bypass`.

High-value permissions:

- `secrets` list/get/watch in a namespace or cluster scope.
- `pods/create`, `pods/exec`, `pods/attach`, `pods/portforward`.
- `pods/ephemeralcontainers` patch/update.
- `deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs` create/update/patch.
- `serviceaccounts/token` create.
- `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings` create/update/patch/escalate/bind.
- `impersonate` on users, groups, serviceaccounts, or nodes.
- `nodes/proxy`, `nodes/exec`, `nodes/log`, `nodes/stats`, `nodes/spec`.
- wildcard verbs or resources.

Finding rules:

- Confirmed allowed permission.
- Denied permission.
- Unknown because collection failed or the token lacked review permissions.
- Escalation path: a low-level permission chain that reaches a higher impact operation, such as create pod plus bypassed admission, bind plus privileged role, or impersonate plus target subject.
- Scope matters: namespace-scoped secret read is not cluster-wide secret read; rolebinding to `cluster-admin` inside one namespace is not the same as cluster-scope `ClusterRoleBinding`.

Prefer EXP template IDs:

- `secret-list-get-verify`
- `pods-exec-verify`
- `nodes-proxy-verify`
- `impersonate-verify`
- `rbac-bind-escalate-verify`
- `serviceaccount-token-api-verify`

Side-effecting templates (explicit authorization required):

- `pod-create-job`
- `ephemeralcontainers-patch`
- `serviceaccount-rbac-persistence`
- `csr-client-cert-persistence`

Output format:

- Group by capability: credential access, workload execution, RBAC escalation, impersonation, node subresources, wildcard/admin.
- Cite SSRR/SSAR fact IDs for every allow/deny/unknown statement.
- For each risky allow, name the minimum next evidence needed before claiming practical exploitability.
