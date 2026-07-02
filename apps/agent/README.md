# KubeTrail Agent Client

`apps/agent` is the experimental Agent SDK client for KubeTrail. It can run through Claude Agent SDK or OpenAI Codex SDK, loads server JSON, exposes controlled KubeTrail MCP tools, applies cloud-native attack-surface skills, and renders EXP Forge bundles.

## Install

```bash
cd apps/agent
npm install
npm run typecheck
```

Node 18+ is required.

## Runtime Configuration

Environment variables:

```text
KUBETRAIL_AGENT_PROVIDER               claude (default) or codex
KUBETRAIL_AGENT_API_KEY                maps to ANTHROPIC_API_KEY for Claude; CODEX_API_KEY/OPENAI_API_KEY for Codex
KUBETRAIL_AGENT_AUTH_TOKEN             maps to ANTHROPIC_AUTH_TOKEN for Claude
KUBETRAIL_AGENT_BASE_URL               maps to ANTHROPIC_BASE_URL for Claude; openai_base_url for Codex
KUBETRAIL_AGENT_MODEL
KUBETRAIL_AGENT_FALLBACK_MODEL
KUBETRAIL_AGENT_HTTPS_PROXY
KUBETRAIL_AGENT_HTTP_PROXY
KUBETRAIL_AGENT_NO_PROXY
KUBETRAIL_AGENT_TIMEOUT_MS
KUBETRAIL_AGENT_MAX_RETRIES
KUBETRAIL_AGENT_MAX_TURNS
KUBETRAIL_AGENT_PATH_TO_CLAUDE
KUBETRAIL_AGENT_PATH_TO_CODEX
KUBETRAIL_AGENT_RUNTIME_DIR
KUBETRAIL_AGENT_CONFIG_DIR              maps to CLAUDE_CONFIG_DIR
KUBETRAIL_AGENT_CODEX_HOME              maps to CODEX_HOME
KUBETRAIL_AGENT_ENABLE_GATEWAY_MODEL_DISCOVERY
KUBETRAIL_AGENT_ALLOW_MATERIALIZE
KUBETRAIL_RESULT_PATH
```

Desktop builds do not embed native Claude or Codex CLI binaries. Install `claude` or `codex` on `PATH`, or set `KUBETRAIL_AGENT_PATH_TO_CLAUDE=/absolute/path/to/claude` and `KUBETRAIL_AGENT_PATH_TO_CODEX=/absolute/path/to/codex`.
For official Claude Code or Codex local CLI mode, leave API key, base URL, and model empty; KubeTrail will use the local `claude`/`codex` login state and the CLI's default model configuration. Fill those fields only for a custom gateway, API key, or forced model.
In Codex official mode, KubeTrail does not set `CODEX_HOME`, so the CLI can read the same default login state used by your terminal. Set `KUBETRAIL_AGENT_CODEX_HOME` or `CODEX_HOME` only when you intentionally want an isolated Codex profile.
In local Node development, `@openai/codex-sdk` can use its optional `@openai/codex` package runtime from `node_modules`. Packaged desktop builds intentionally avoid embedding that native runtime because it is hundreds of MB.
Agent runtime data defaults to the user's application data directory under `KubeTrail/runtime`; set `KUBETRAIL_AGENT_RUNTIME_DIR` to override it.

Example:

```bash
export KUBETRAIL_AGENT_API_KEY=...
export KUBETRAIL_AGENT_BASE_URL=https://gateway.example/v1
export KUBETRAIL_AGENT_MODEL=claude-sonnet-4-6
export KUBETRAIL_RESULT_PATH=/path/to/dbus.json
```

Codex example:

```bash
export KUBETRAIL_AGENT_PROVIDER=codex
export KUBETRAIL_AGENT_API_KEY=...
export KUBETRAIL_AGENT_MODEL=gpt-5.4
export KUBETRAIL_RESULT_PATH=/path/to/dbus.json
```

The client clears ambient proxy variables before launching the Agent SDK process. Use the `KUBETRAIL_AGENT_*_PROXY` variables or the web Provider panel when a proxy is required.

## CLI Chat

```bash
npm run chat -- --input ../../dbus.json --message "分析当前最高价值的攻击面，给出证据和验证模板"
```

Select provider:

```bash
npm run chat -- --provider codex --input ../../dbus.json --message "列出 RBAC 提权路径"
```

JSON event stream:

```bash
npm run chat -- --input ../../dbus.json --json --message "列出 RBAC 提权路径"
```

Inspect public runtime configuration:

```bash
npm run env
```

Run the KubeTrail MCP server over stdio for Codex:

```bash
npm run mcp
```

## Web UI

```bash
npm run serve -- --host 127.0.0.1 --port 18080
```

Open:

```text
http://127.0.0.1:18080
```

The Provider panel accepts API key, base URL, model, proxy, timeout, and retry overrides. Values entered in the page are sent with chat requests and are not written to server-side files. `Save Tab` stores them only in browser `sessionStorage`.

## Controlled Tools

The Agent can use KubeTrail MCP tools:

```text
kubetrail_load_result
kubetrail_summary
kubetrail_list_facts
kubetrail_get_fact
kubetrail_list_sensitive_refs
kubetrail_materialize_sensitive
kubetrail_list_exp_templates
kubetrail_generate_exp_plan
```

Sensitive values are represented as `sensitive://` refs. Raw materialization is disabled unless `KUBETRAIL_AGENT_ALLOW_MATERIALIZE=1` is set.

## Attack-Surface Skills

Skills are authored under `.claude/skills/*/SKILL.md`. When the Codex provider starts, KubeTrail syncs those files into Codex's repo-scoped `.agents/skills/*/SKILL.md` layout so both providers use the same skill content.

Current skills:

```text
k8s-rbac-analysis
serviceaccount-secret-material
pod-escape-surface
kubelet-runtime-etcd-bypass
exposed-management-interfaces
public-workload-rce-surface
cloud-metadata-analysis
image-registry-supply-chain
workload-controller-persistence
network-lateral-movement
service-ingress-exposure
admission-policy-governance
operator-crd-controller-abuse
observability-defense-evasion
resource-hijack-dos
windows-container-surface
exp-generation
```

The skill set is intentionally split by attack-surface boundary so that RBAC, local Pod escape, cloud identity, network reachability, admission policy, and EXP planning do not duplicate each other.

## EXP Forge

List templates:

```bash
npm run exp -- list
```

Render command bundle:

```bash
npm run exp -- render --template cloud-metadata-verify --set provider=aws
```

Render Kubernetes object bundle:

```bash
npm run exp -- render \
  --template pod-hostpath \
  --set namespace=default \
  --set serviceAccount=default \
  --set targetPath=/var/run
```

Render source-build bundle:

```bash
npm run exp -- render \
  --template runtime-socket-verify \
  --set socketPath=/run/containerd/containerd.sock
```

Render prebuilt binary wrapper:

```bash
npm run exp -- render \
  --template external-cve-poc \
  --set pocId=CVE-xxxx \
  --set os=linux \
  --set arch=amd64 \
  --set binaryName=poc
```

Bundles default to `KUBETRAIL_AGENT_RUNTIME_DIR/exp/generated/<run-id>`. Use `--out <dir>` to choose a path. Each bundle contains `manifest.json`, `README.md`, and the command, YAML, patch, source, or binary wrapper artifacts required for operation.

More details: [exp/README.md](exp/README.md).
