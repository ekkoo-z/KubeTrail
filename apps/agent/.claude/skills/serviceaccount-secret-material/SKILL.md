---
name: serviceaccount-secret-material
description: Analyze exposed Kubernetes tokens, Secrets, kubeconfigs, registry credentials, environment secrets, and credential-sweep sensitive refs.
---

# ServiceAccount And Secret Material

Use this skill when facts mention `sensitive://` refs, service account tokens, Kubernetes Secrets, kubeconfig, image pull secrets, registry auth, config files, environment variables, or credential sweep results.

Scope boundary:

- Owns material presence and sensitivity, not authorization. Use `k8s-rbac-analysis` to decide what the token can do.
- Owns generic cloud credential files and env values. Use `cloud-metadata-analysis` only when the evidence is metadata or workload identity exchange.
- Do not request raw sensitive material unless the user explicitly asks and materialization is enabled.

High-value evidence:

- Mounted service account token refs, bound token volume hints, legacy non-expiring token secrets, writable token projection.
- Kubernetes Secret refs, secret-backed env vars, secret volumes, configmaps holding confidential strings.
- Kubeconfig files, client cert/key refs, bearer tokens, exec auth plugins.
- Docker config JSON, image pull secrets, registry usernames/tokens, private registry endpoints.
- Cloud credential files such as AWS credentials/config, GCP ADC, Azure profile, OCI config, `.env`, `.netrc`, Git credentials, SSH keys.
- Sensitive ref metadata: kind, factId, source, bytes, sha256, materializable.

Finding rules:

- Confirmed high: materialized-sensitive ref exists for a token/secret/kubeconfig/registry/cloud key and is reachable from the compromised context.
- Medium: secret reference or mount exists but raw value was redacted or not collected.
- Low: file path or env key name suggests credentials but no value/ref was collected.
- Unknown: credential sweep disabled or collector denied local filesystem/env access.

Useful templates:

- `secret-material-review`
- `secret-list-get-verify`
- `serviceaccount-token-api-verify`
- `registry-auth-verify`

Side-effecting templates (explicit authorization required):

- `pull-secret-injection`
- `csr-client-cert-persistence`

Output notes:

- Report only refs and metadata, not raw values.
- State likely blast radius only when paired with RBAC, cloud identity, registry, or workload evidence.
- Call out explicit opt-in requirements such as `--credential-sweep` and `KUBETRAIL_AGENT_ALLOW_MATERIALIZE=1`.
