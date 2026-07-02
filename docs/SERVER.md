# KubeTrail Server Collector

`kubetrail-server` is the in-pod evidence collector. It gathers local and Kubernetes API facts and writes one JSON document for offline or interactive client analysis.

The server does not rank exploitability and does not generate EXP output. Its job is to preserve evidence, collector status, and structured errors so the client can reason from facts.

## Quick Start

Run inside a pod:

```bash
./kubetrail-server --mode safe --output dbus.json
```

Run full collection:

```bash
./kubetrail-server --mode full --output dbus.json
```

Run against a local kubeconfig for testing:

```bash
./kubetrail-server --mode safe --kubeconfig ~/.kube/config --output dbus.json
```

Write to stdout:

```bash
./kubetrail-server --mode safe --output -
```

## Options

```text
--mode safe|full
  Short form: -m safe|full.
  Collection mode. Default: safe.

--output dbus.json|-
  Short form: -o dbus.json|-.
  Output JSON path or stdout. Default: dbus.json. JSON is compact by default.

--pretty
  Short form: -p.
  Pretty-print output JSON for manual inspection. This increases file size.

--timeout 60s
  Short form: -t 60s.
  Overall collection timeout.

--sensitive raw|redact|metadata
  Short form: -v raw|redact|metadata.
  Sensitive value handling. Default: raw.

--rbac-mode focused|full
  Short form: -r focused|full.
  Kubernetes RBAC access review mode. Default: focused.

  focused checks high-signal permissions and common attack paths only:
  Secret read, pod create/exec/attach/port-forward, ephemeral container patch,
  workload create, RBAC bind/escalate, impersonation, ServiceAccount token
  creation, nodes/proxy, mutating webhooks, CSR approval, and kube-system
  Secret access. It does not expand non-admin wildcard rules into additional
  SelfSubjectAccessReview calls.

  full runs the complete access-review matrix and wildcard expansion. Use this
  for deep audit/reporting when extra API audit noise is acceptable.

--max-items 100
  Short form: -n 100.
  Maximum items per Kubernetes list request.

--credential-sweep
  Short form: -c.
  Read common credential files and include results in output. Default: enabled.
  Use --credential-sweep=false or -c=false to disable.

--secretoutput secret-audit.json
  Short form: -secret secret-audit.json.
  Write a separate JSON file containing visible legacy ServiceAccount token
  Secrets and per-token SSRR/SSAR permission results. This is explicit opt-in
  because the file contains raw token material.

--kubeconfig /path/to/kubeconfig
  Short form: -k /path/to/kubeconfig.
  Use kubeconfig instead of in-cluster ServiceAccount credentials.

--scan all|lpe|escape|rbac
  Short form: -s all|lpe|escape|rbac.
  Limit collection and findings categories. Comma-separated values are supported.
```

## Collection Modes

### Safe

Safe mode collects local read-only evidence and Kubernetes API read-only facts:

- process identity and environment
- service account files and namespace hints
- `/proc`, cgroups, namespaces, mounts, and process hints
- filesystem and volume indicators
- `/dev` and runtime socket hints
- node-local interface and hostname context
- Kubernetes version and discovery
- current Pod and namespace context
- RBAC self-review through SSRR/SSAR where permitted
- high-value access review matrix
- structured Pod profile
- namespace, node, network, policy, and object discovery
- credential file sweep unless `--credential-sweep=false` or `-c=false` is set

Kubernetes API access uses official Go clients. In-cluster collection uses `rest.InClusterConfig()` through the mounted ServiceAccount. Local testing can use `--kubeconfig`.

### Full

Full mode includes safe collectors and adds active validation facts:

- DNS service discovery queries
- cloud metadata endpoint HTTP probes
- Kubernetes Admission server-side dry-run Pod create tests
- syscall probing

Full mode may create observable events such as DNS requests, HTTP requests to metadata endpoints, Admission dry-run requests, and syscall attempts.

## Collector IDs

Safe collectors:

```text
identity
environment
serviceaccount
proc
filesystem
node_local
runtime_local
k8s_context
k8s_permissions
k8s_profile
k8s_objects
credential_sweep        # enabled by default; disabled by --credential-sweep=false or -c=false
```

Additional artifact-only collection:

```text
sa_token_audit          # only when --secretoutput/-secret is set
```

Full-only collectors:

```text
dns_services
cloud_metadata
admission_dryrun
syscalls
```

Collector failures are reported as structured errors. A collector failure should not abort the whole scan unless the top-level timeout or output write fails.

## Kubernetes API Behavior

The server avoids `kubectl`. It uses:

- typed Kubernetes clients for stable core operations such as authorization reviews
- discovery and dynamic clients for generic resource enumeration
- in-cluster ServiceAccount credentials by default
- kubeconfig only when explicitly provided for testing

KubeTrail uses discovery-driven read operations only where the current identity appears allowed.

KubeTrail sets its Kubernetes client default rate limit to QPS 50 and burst 100. This prevents large SSRR-to-SSAR wildcard expansions from timing out inside client-go's local rate limiter during the default 60 second collection window.

By default, the server records focused high-value permission evidence such as:

- Secret read/list
- pod create/exec/attach/portforward
- ephemeral container patch/update
- workload controller create/update
- serviceaccounts/token create
- RBAC bind/escalate/update paths
- impersonation
- node subresources such as `nodes/proxy`
- wildcard verbs/resources

Use `--rbac-mode full` to run the complete matrix, including lower-signal
checks and expanded wildcard SSAR probes.

`nodes/proxy` is recorded as an authorization signal. Direct active probing belongs to full-mode validation or client-side EXP planning.

## Sensitive Data

Default sensitive mode is `raw`, which preserves values in the output JSON. This is useful for local authorized research but should be handled as sensitive assessment material.

Modes:

- `raw`: include collected values.
- `redact`: replace sensitive values with redaction markers.
- `metadata`: keep metadata such as presence, length, hash, or shape where available.

Credential sweep is enabled by default. It looks for common Kubernetes, cloud, registry, CI/CD, and workload identity credential files. Use `--credential-sweep=false` or `-c=false` to disable it.

ServiceAccount token audit is disabled by default. When `--secretoutput` or `-secret` is set, KubeTrail reads existing `kubernetes.io/service-account-token` Secrets visible to the current identity, writes their decoded token values to the separate audit JSON, and then uses each token as a bearer token against the same API server/CA to run:

- SelfSubjectRulesReview in the token Secret namespace
- the standard high-value SelfSubjectAccessReview matrix
- wildcard SSRR expansion through additional SSAR checks when SSRR succeeds

Signal source: Kubernetes `v1/Secret` objects of type `kubernetes.io/service-account-token`, plus `authorization.k8s.io/v1` SSRR/SSAR responses produced by each exported token.

Required permission or environment: in-cluster API connectivity; `list secrets` in at least one namespace to export token Secrets; `list namespaces` is optional and only expands coverage across namespaces. If namespace listing is denied, the audit falls back to the current namespace. Each exported token must be accepted by the API server for permission review to succeed.

Expected positive evidence: audit items with `token`, `serviceAccount`, successful `selfSubjectRules`, and `highValueAccess` entries where `allowed:true` identifies concrete verb/resource scope.

Expected negative evidence: top-level errors for denied namespace/Secret listing, item-level SSRR/SSAR errors for expired or invalid tokens, empty `items` on Kubernetes v1.24+ clusters that do not use legacy auto-created token Secrets, or `allowed:false` high-value checks for constrained tokens.

## Output Schema

The server emits `kubetrail.server/v1`.

Top-level fields:

```text
schemaVersion
run
target
mode
collectors
facts
findings
errors
```

The token-audit artifact emits `kubetrail.sa-token-audit/v1` and is intentionally separate from the main server result. It is always raw sensitive material and should be handled as credential evidence.

Collector entries contain:

```text
id
mode
status
duration
factCount
sideEffects
errors
```

Facts contain:

```text
id
collector
category
source
sensitive
value
```

Findings contain the lightweight risk summary produced from collected facts:

```text
severity
category
title
description
evidence
```

Errors contain:

```text
source
message
```

Clients should treat `facts` as the primary evidence surface and preserve `collector` and `source` when citing findings.

## Typical Research Flow

1. Run `kubetrail-server --mode safe --output dbus.json`.
2. Analyze `dbus.json` with `kubetrail-client` or `apps/agent`.
3. If evidence is missing, rerun with the narrowest useful option such as `--rbac-mode full` or `--mode full`; use `--credential-sweep=false` or `-c=false` when credential file collection is not desired.
4. Use client-side EXP templates to render verification bundles.
5. Keep server JSON and EXP bundles inside the authorized assessment workspace.
