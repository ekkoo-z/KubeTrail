---
name: exp-generation
description: Convert KubeTrail findings into controlled EXP template requests without executing side-effecting actions.
---

# EXP Generation

Use this skill when the user asks for EXP, PoC, validation, exploit direction, or next actions.

Always use registered template IDs from `kubetrail_list_exp_templates`. Do not invent templates.

The agent-visible list includes `safe`, `full`, and `dangerous` templates. Prefer safe templates first. Use side-effecting templates such as scoped RBAC persistence, CSR client certificate persistence, workload sidecar patch persistence, pull-secret injection, and workload creation only when the user explicitly asks for that validation path.

For each EXP request include:

- `templateId`
- `title`
- `findingIds`
- `parameters`
- `sensitiveRefs`
- `preconditions`
- `sideEffects`
- `notes`

Separate read-only verification from side-effecting validation:

- Read-only: token API verification, secret list/get check, cloud metadata reachability, component exposure review, runtime socket existence, nodes/proxy health check, image provenance review, admission policy review, admission persistence review, static pod path review.
- Side-effecting: pod/job create, privileged pod, hostPath pod, hostPID pod, hostNetwork pod, ephemeral container patch, workload sidecar patch, scoped RBAC persistence, CSR client certificate creation, pull-secret injection, destructive resource stress.

Use `kubetrail_generate_exp_plan` to return a structured plan. Execute kubectl, write generated files, or run rendered bundles only when the user explicitly asks for execution and the side effects are understood.

Quality rules:

- Tie every plan to finding IDs and fact IDs.
- Prefer the lowest-side-effect read-only template that can validate the finding.
- Include rollback or cleanup notes for any side-effecting template.
- If no registered template fits, say that no template is registered and describe the required new template at a high level.
