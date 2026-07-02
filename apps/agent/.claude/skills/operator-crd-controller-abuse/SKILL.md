---
name: operator-crd-controller-abuse
description: Analyze Operators, CRDs, and controllers whose high privileges can be indirectly abused through lower-privileged custom resources.
---

# Operator CRD Controller Abuse

Use this skill when facts mention CRDs, custom resources, Operators, controllers, reconciliation, ownerReferences, cross-namespace references, controller ServiceAccounts, or generated workloads/secrets.

Scope boundary:

- Owns indirect privilege through controllers and CRDs.
- Use `k8s-rbac-analysis` for direct permissions on CRDs and controller ServiceAccounts.
- Use `workload-controller-persistence` for objects created by controllers after the abuse path is established.
- Use `serviceaccount-secret-material` for secrets exposed by controller behavior.

High-value evidence:

- Controller ServiceAccount with cluster-admin or broad create/update/list/get on secrets, pods, deployments, webhooks, CRDs.
- User identity can create/update custom resources watched by a high-privilege controller.
- CRD fields referencing Secrets, ConfigMaps, service accounts, namespaces, image names, pod templates, backup/restore destinations, webhooks, or external URLs.
- Cross-namespace references where a namespaced user can influence resources outside their namespace.
- Status/events showing controller-created workloads, secrets, roles, or webhooks.

Finding rules:

- Confirmed high: low-privileged subject can modify a CR that causes a high-privilege controller to create pods, read secrets, write roles, or cross namespaces.
- Medium: high-privilege operator exists and tenant can modify related CRDs, but effect is unconfirmed.
- Low: operator has broad RBAC but no user path to controlled CRDs.
- Unknown: CRDs discovered but controller RBAC or allowed subject permissions missing.

Useful templates:

- `operator-crd-abuse-review`
- `rbac-bind-escalate-verify`
- `controller-persistence-review`

Side-effecting templates (explicit authorization required):

- `workload-patch-sidecar-persistence`
- `pull-secret-injection`

Output notes:

- Describe the actor-controller-target chain.
- Avoid claiming the controller will execute a field unless evidence shows that field is consumed.
- Ask for discovery/dynamic-client CRD facts and controller RBAC when missing.
