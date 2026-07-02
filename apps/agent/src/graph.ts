import { KubeTrailContextStore, type SanitizedFact, type SanitizedResult } from "./context.js";
import { buildLpeCatalogFindings, lpeExpParamsForText, lpeTemplatesForText } from "./lpe.js";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "info" | "blocked" | "unknown";

export type GraphNode = {
  id: string;
  label: string;
  type: string;
  risk: RiskLevel;
  subtitle?: string;
  tags: string[];
  evidence: string[];
  materialRef?: string;
  detail?: Record<string, unknown>;
};

export type GraphEdge = {
  id: string;
  from: string;
  to: string;
  label: string;
  type: string;
  risk: RiskLevel;
  evidence: string[];
};

export type GraphFinding = {
  id: string;
  title: string;
  category: "escape" | "exploit" | "lpe" | "material" | "blocked" | "context";
  severity: RiskLevel;
  description: string;
  evidence: string[];
  nodes: string[];
  templates: string[];
  nextSteps: string[];
  origin?: "graph" | "document" | "catalog" | "agent";
  confidence?: "confirmed" | "probable" | "signal" | "blocked" | "unknown";
  expParams?: Record<string, string>;
};

export type AttackGraph = {
  summary: {
    path: string;
    schemaVersion?: string;
    mode?: string;
    namespace?: string;
    podName?: string;
    apiServer?: string;
    runId?: string;
    factCount: number;
    collectorCount: number;
    errorCount: number;
  };
  stats: Record<string, number>;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: GraphFinding[];
};

type SecretRecord = {
  namespace: string;
  name: string;
  type: string;
  item: Record<string, unknown>;
};

type Builder = {
  nodes: Map<string, GraphNode>;
  edges: Map<string, GraphEdge>;
  findings: Map<string, GraphFinding>;
};

const riskRank: Record<RiskLevel, number> = {
  blocked: 0,
  info: 1,
  unknown: 2,
  low: 3,
  medium: 4,
  high: 5,
  critical: 6,
};

export async function loadAttackGraph(inputPath: string): Promise<AttackGraph> {
  const store = new KubeTrailContextStore(inputPath);
  const result = await store.load(inputPath);
  return buildAttackGraph(result);
}

export function buildAttackGraph(result: SanitizedResult): AttackGraph {
  const builder: Builder = {
    nodes: new Map(),
    edges: new Map(),
    findings: new Map(),
  };
  const facts = new Map(result.facts.map((fact) => [fact.id, fact]));
  const target = asRecord(result.target);
  const run = asRecord(result.run);
  const podValue = rawFactValue(result, facts.get("k8s_profile.current_pod_structured")) ?? rawFactValue(result, facts.get("k8s_context.current_pod"));
  const pod = asRecord(podValue);
  const podMeta = asRecord(pod.metadata);
  const podSpec = asRecord(pod.spec);
  const namespace = stringValue(target.namespace) ?? stringValue(podMeta.namespace);
  const podName = stringValue(target.podName) ?? stringValue(podMeta.name);
  const serviceAccount = stringValue(podSpec.serviceAccountName) ?? "default";
  const nodeName = stringValue(podSpec.nodeName);
  const apiServer = stringValue(target.apiServer);

  const apiNodeId = "api:kubernetes";
  addNode(builder, {
    id: apiNodeId,
    label: "Kubernetes API",
    type: "api",
    risk: "info",
    subtitle: apiServer,
    tags: ["in-cluster"],
    evidence: ["target.apiServer"],
  });

  const namespaceNodeId = namespace ? `namespace:${namespace}` : "namespace:unknown";
  addNode(builder, {
    id: namespaceNodeId,
    label: namespace ?? "unknown namespace",
    type: "namespace",
    risk: "info",
    tags: ["scope"],
    evidence: ["target.namespace"],
  });
  addEdge(builder, apiNodeId, namespaceNodeId, "hosts", "scope", "info", ["target"]);

  const podNodeId = podName && namespace ? podId(namespace, podName) : "pod:current";
  addNode(builder, {
    id: podNodeId,
    label: podName ?? "current pod",
    type: "pod",
    risk: "medium",
    subtitle: namespace,
    tags: ["current"],
    evidence: ["k8s_profile.current_pod_structured"],
    detail: { namespace, podName, serviceAccount, nodeName },
  });
  addEdge(builder, namespaceNodeId, podNodeId, "contains", "ownership", "info", ["k8s_profile.current_pod_structured"]);

  const serviceAccountNodeId = namespace ? serviceAccountId(namespace, serviceAccount) : `serviceaccount:${serviceAccount}`;
  addNode(builder, {
    id: serviceAccountNodeId,
    label: serviceAccount,
    type: "serviceaccount",
    risk: "high",
    subtitle: namespace,
    tags: ["current identity"],
    evidence: ["k8s_profile.current_pod_structured", "serviceaccount.mounted"],
    detail: { namespace, serviceAccount },
  });
  addEdge(builder, podNodeId, serviceAccountNodeId, "uses", "identity", "high", ["k8s_profile.current_pod_structured"]);

  if (nodeName) {
    const nodeId = `node:${nodeName}`;
    addNode(builder, {
      id: nodeId,
      label: nodeName,
      type: "node",
      risk: "medium",
      tags: ["scheduled node"],
      evidence: ["k8s_profile.current_pod_structured"],
    });
    addEdge(builder, podNodeId, nodeId, "scheduled on", "runtime", "medium", ["k8s_profile.current_pod_structured"]);
  }

  addCurrentPodSurface(builder, result, facts, podNodeId, podSpec);
  addProcessSurface(builder, result, facts, podNodeId);
  addServiceAccountMaterial(builder, result, facts, serviceAccountNodeId);
  const hasClusterAdmin = addAuthorization(builder, result, facts, serviceAccountNodeId);
  addPermittedObjects(builder, result, facts, namespaceNodeId, serviceAccountNodeId, podNodeId, namespace, podName);
  addDocumentFindings(builder, result);
  addLpeCatalogFindings(builder, result);
  addCollectionErrors(builder, result);
  addCompoundFindings(builder);
  if (hasClusterAdmin) {
    addClusterAdminFinding(builder, serviceAccountNodeId, namespace, serviceAccount, podName);
  }

  const stats = calculateStats(builder);
  return {
    summary: {
      path: result.path,
      schemaVersion: result.schemaVersion,
      mode: result.mode,
      namespace,
      podName,
      apiServer,
      runId: stringValue(run.id),
      factCount: result.facts.length,
      collectorCount: result.collectors.length,
      errorCount: result.errors.length,
    },
    stats,
    nodes: Array.from(builder.nodes.values()),
    edges: Array.from(builder.edges.values()),
    findings: Array.from(builder.findings.values()).sort((a, b) => riskRank[b.severity] - riskRank[a.severity]),
  };
}

function addDocumentFindings(builder: Builder, result: SanitizedResult): void {
  for (const finding of result.findings) {
    const title = stringValue(finding.title) ?? "Document finding";
    const description = stringValue(finding.description) ?? "";
    const rawCategory = stringValue(finding.category) ?? "context";
    const evidence = splitEvidence(finding.evidence);
    const text = `${title} ${description} ${evidence.join(" ")}`;
    const category = documentFindingCategory(rawCategory, text);
    const templates = documentFindingTemplates(category, text);
    const expParams = category === "lpe" ? lpeExpParamsForText(text, templates) : undefined;
    addFinding(builder, {
      id: `document:${stableId(`${rawCategory}:${title}`)}`,
      title,
      category,
      severity: normalizeRisk(finding.severity),
      description,
      evidence,
      nodes: [],
      templates,
      nextSteps: documentFindingNextSteps(category, evidence, templates),
      origin: "document",
      confidence: confidenceFromDocument(rawCategory, finding.severity, finding.confidence, text),
      expParams,
    });
  }
}

function addLpeCatalogFindings(builder: Builder, result: SanitizedResult): void {
  for (const finding of buildLpeCatalogFindings(result)) {
    addFinding(builder, {
      ...finding,
      category: "lpe",
      nodes: [],
      origin: "catalog",
    });
  }
}

function documentFindingCategory(rawCategory: string, text: string): GraphFinding["category"] {
  const category = rawCategory.toLowerCase();
  const lowered = text.toLowerCase();
  if (category === "lpe") return "lpe";
  if (category === "escape") return "escape";
  if (category === "material") return "material";
  if (category === "blocked") return "blocked";
  if (category === "context") return "context";
  if (category === "rbac") {
    return lowered.includes("secret") || lowered.includes("token") ? "material" : "exploit";
  }
  if (lowered.includes("secret") || lowered.includes("token") || lowered.includes("credential")) return "material";
  if (lowered.includes("rbac") || lowered.includes("ssar") || lowered.includes("pods/exec")) return "exploit";
  return "context";
}

function documentFindingTemplates(category: GraphFinding["category"], text: string): string[] {
  const lowered = text.toLowerCase();
  if (category === "lpe") return lpeTemplatesForText(lowered);
  const templates = new Set<string>();
  if (category === "escape") {
    if (lowered.includes("runtime socket") || lowered.includes("containerd") || lowered.includes("docker.sock") || lowered.includes("pouch")) {
      templates.add("runtime-socket-verify");
    }
    if (lowered.includes("hostpath") || lowered.includes("host path")) templates.add("pod-hostpath");
    if (lowered.includes("privileged")) templates.add("pod-privileged");
    if (lowered.includes("hostpid")) templates.add("pod-hostpid");
    if (lowered.includes("hostnetwork")) templates.add("pod-hostnetwork");
  }
  if (category === "exploit") {
    if (lowered.includes("pods/exec") || lowered.includes("pods_exec")) templates.add("pods-exec-verify");
    if (lowered.includes("create") && (lowered.includes("pod") || lowered.includes("job") || lowered.includes("deployment"))) templates.add("pod-create-job");
    if (lowered.includes("bind") || lowered.includes("escalate") || lowered.includes("clusterrole")) templates.add("rbac-bind-escalate-verify");
    if (lowered.includes("impersonate")) templates.add("impersonate-verify");
    if (lowered.includes("nodes/proxy") || lowered.includes("nodes_proxy")) templates.add("nodes-proxy-verify");
  }
  if (category === "material") {
    if (lowered.includes("secret")) templates.add("secret-material-review");
    if (lowered.includes("serviceaccount") || lowered.includes("service account") || lowered.includes("token")) templates.add("serviceaccount-token-api-verify");
  }
  return Array.from(templates);
}

function documentFindingNextSteps(category: GraphFinding["category"], evidence: string[], templates: string[]): string[] {
  const steps: string[] = [];
  if (category === "lpe") {
    steps.push("复核版本、补丁 backport、SUID/capability、内核配置和运行用户后再进入 EXP Forge。");
  } else if (category === "escape") {
    steps.push("结合运行态挂载、容器权限和 admission 约束做受控验证。");
  } else if (category === "exploit" || category === "material") {
    steps.push("用 SSAR/SSRR 和 permitted object 证据限定 namespace、resource、verb 和 blast radius。");
  } else if (category === "blocked") {
    steps.push("保留为受阻路径；权限或角色变化后重新采集。");
  }
  if (templates.length) {
    steps.push("可用模板：" + templates.join(", "));
  }
  if (evidence.length) {
    steps.push("优先复核证据：" + evidence.join(", "));
  }
  return steps;
}

function confidenceFromDocument(rawCategory: string, severity: unknown, confidence: unknown, text = ""): GraphFinding["confidence"] {
  const category = rawCategory.toLowerCase();
  const explicit = stringValue(confidence)?.toLowerCase();
  if (["confirmed", "probable", "signal", "blocked", "unknown"].includes(explicit ?? "")) {
    return explicit as GraphFinding["confidence"];
  }
  const risk = normalizeRisk(severity);
  if (category === "blocked") return "blocked";
  if (category === "lpe" && lpeFindingLooksHeuristic(text)) return "signal";
  if (risk === "critical" || risk === "high") return "probable";
  if (risk === "medium" || risk === "low") return "signal";
  return "unknown";
}

function lpeFindingLooksHeuristic(text: string): boolean {
  const lowered = text.toLowerCase();
  return [
    "heuristic",
    "vendor backport",
    "vendor backports",
    "advisory status",
    "version-only",
    "kernel range",
    "upstream range",
    "pre-fix branch",
    "was not confirmed",
  ].some((needle) => lowered.includes(needle));
}

export async function materializeGraphRef(inputPath: string, ref: string): Promise<unknown> {
  const store = new KubeTrailContextStore(inputPath);
  const result = await store.load(inputPath);
  if (ref.startsWith("sensitive://k8s-secret/")) {
    const parts = ref.slice("sensitive://k8s-secret/".length).split("/");
    if (parts.length !== 2) {
      throw new Error(`invalid Kubernetes Secret ref: ${ref}`);
    }
    const namespace = decodeURIComponent(parts[0]);
    const name = decodeURIComponent(parts[1]);
    const secret = findSecret(result, namespace, name);
    if (!secret) {
      throw new Error(`unknown Kubernetes Secret ref: ${ref}`);
    }
    return withDecodedSecretData(secret.item);
  }
  const value = result.sensitiveMaterial.get(ref);
  if (value === undefined) {
    throw new Error(`unknown sensitive ref: ${ref}`);
  }
  return value;
}

function addCurrentPodSurface(builder: Builder, result: SanitizedResult, facts: Map<string, SanitizedFact>, podNodeId: string, podSpec: Record<string, unknown>): void {
  const containers = arrayOfRecords(podSpec.containers);
  const volumes = arrayOfRecords(podSpec.volumes);
  const volumeByName = new Map(volumes.map((volume) => [stringValue(volume.name) ?? "", volume]));
  let privilegedContainer = false;
  let hostPathCount = 0;
  let serviceAccountSecret = false;

  for (const container of containers) {
    const name = stringValue(container.name) ?? "container";
    const containerNodeId = `${podNodeId}/container:${name}`;
    const securityContext = asRecord(container.securityContext);
    const privileged = securityContext.privileged === true;
    const allowPrivilegeEscalation = securityContext.allowPrivilegeEscalation === true;
    const tags = [privileged ? "privileged" : "container"];
    if (allowPrivilegeEscalation) tags.push("allowPrivilegeEscalation");
    privilegedContainer ||= privileged;
    addNode(builder, {
      id: containerNodeId,
      label: name,
      type: "container",
      risk: privileged ? "critical" : "info",
      subtitle: stringValue(container.image),
      tags,
      evidence: ["k8s_profile.current_pod_structured"],
      detail: { image: stringValue(container.image), privileged, allowPrivilegeEscalation },
    });
    addEdge(builder, podNodeId, containerNodeId, "contains", "runtime", privileged ? "critical" : "info", ["k8s_profile.current_pod_structured"]);

    for (const mount of arrayOfRecords(container.volumeMounts)) {
      const volumeName = stringValue(mount.name);
      const volume = volumeName ? volumeByName.get(volumeName) : undefined;
      const hostPath = asRecord(volume?.hostPath);
      const hostPathPath = stringValue(hostPath.path);
      if (hostPathPath) {
        hostPathCount++;
        const risk = scoreHostPath(hostPathPath);
        const hostPathNodeId = hostPathId(hostPathPath);
        addNode(builder, {
          id: hostPathNodeId,
          label: hostPathPath,
          type: "hostpath",
          risk,
          subtitle: stringValue(mount.mountPath),
          tags: ["hostPath", volumeName ?? ""].filter(Boolean),
          evidence: ["k8s_profile.current_pod_structured"],
          detail: { volumeName, mountPath: stringValue(mount.mountPath), readOnly: mount.readOnly === true, hostPathType: stringValue(hostPath.type) },
        });
        addEdge(builder, containerNodeId, hostPathNodeId, stringValue(mount.mountPath) ?? "mount", "mount", risk, ["k8s_profile.current_pod_structured"]);
      }

      const secret = asRecord(volume?.secret);
      const secretName = stringValue(secret.secretName);
      if (secretName) {
        serviceAccountSecret ||= secretName.includes("token");
        const namespace = stringValue(asRecord(result.target).namespace);
        const secretNodeId = namespace ? secretId(namespace, secretName) : `secret:${secretName}`;
        addNode(builder, {
          id: secretNodeId,
          label: secretName,
          type: "secret",
          risk: "high",
          subtitle: namespace,
          tags: ["mounted secret"],
          evidence: ["k8s_profile.current_pod_structured"],
          materialRef: namespace ? secretRef(namespace, secretName) : undefined,
          detail: { mountPath: stringValue(mount.mountPath), readOnly: mount.readOnly === true },
        });
        addEdge(builder, containerNodeId, secretNodeId, stringValue(mount.mountPath) ?? "secret mount", "secret", "high", ["k8s_profile.current_pod_structured"]);
      }
    }
  }

  if (privilegedContainer || hostPathCount > 0) {
    const severity = privilegedContainer && hostPathCount > 0 ? "critical" : "high";
    addNode(builder, {
      id: podNodeId,
      label: builder.nodes.get(podNodeId)?.label ?? "current pod",
      type: "pod",
      risk: severity,
      tags: [privilegedContainer ? "privileged sidecar" : "", hostPathCount > 0 ? `${hostPathCount} hostPath mounts` : ""].filter(Boolean),
      evidence: ["k8s_profile.current_pod_structured"],
    });
    addFinding(builder, {
      id: "escape-current-pod-privileged-hostpath",
      title: "当前 Pod 存在逃逸候选面",
      category: "escape",
      severity,
      description: privilegedContainer
        ? "Pod 规格中存在 privileged 容器，并且挂载了多个 hostPath。是否可直接逃逸取决于当前交互容器与 privileged sidecar 的可达性、共享卷和 admission/运行时隔离。"
        : "Pod 规格中存在 hostPath 挂载，部分路径指向宿主运行时或平台目录。需要验证挂载可读写性和路径内是否有运行时 socket 或敏感文件。",
      evidence: ["k8s_profile.current_pod_structured"],
      nodes: [podNodeId],
      templates: privilegedContainer ? ["pod-privileged", "pod-hostpath"] : ["pod-hostpath"],
      nextSteps: ["在 full 模式或受控验证 Pod 中确认 mount 权限、容器边界和运行时隔离。", "避免直接声称已逃逸；先确认是否能触达 privileged 容器或宿主关键路径。"],
    });
  }

  if (serviceAccountSecret) {
    addFinding(builder, {
      id: "material-mounted-serviceaccount-token",
      title: "ServiceAccount token 已挂载",
      category: "material",
      severity: "high",
      description: "当前 Pod 挂载了 ServiceAccount token，可与 RBAC 结果组合评估 Kubernetes API 影响面。",
      evidence: ["serviceaccount.mounted", "k8s_profile.current_pod_structured"],
      nodes: [podNodeId],
      templates: ["serviceaccount-token-api-verify"],
      nextSteps: ["点击 token/Secret 节点查看测试环境中的材料，随后以 SSAR/SSRR 结果限定影响范围。"],
    });
  }
}

function addProcessSurface(builder: Builder, result: SanitizedResult, facts: Map<string, SanitizedFact>, podNodeId: string): void {
  const status = asRecord(rawFactValue(result, facts.get("proc.status_security")));
  if (!Object.keys(status).length) return;
  const uid = stringValue(status.uid);
  const seccomp = stringValue(status.seccomp);
  const noNewPrivs = stringValue(status.noNewPrivs);
  const capabilities = asRecord(status.capabilities);
  const effectiveCaps = stringValue(capabilities.effective);
  const root = uid?.startsWith("0\t") || uid === "0";
  const noSeccomp = seccomp === "0";
  const noNewPrivsDisabled = noNewPrivs === "0"; // "0" means not set → weaker security
  const broadCaps = Boolean(effectiveCaps && effectiveCaps !== "0000000000000000");
  const dangerousCaps = hasDangerousCapability(effectiveCaps);
  const tags = [root ? "uid=0" : "", noSeccomp ? "seccomp=0" : "", noNewPrivsDisabled ? "noNewPrivs=0" : "", broadCaps ? "capabilities" : "", dangerousCaps ? "dangerous-caps" : ""].filter(Boolean);
  if (!tags.length) return;

  // Score-based risk: each weakening signal adds weight
  let score = 0;
  if (root) score += 1;
  if (noSeccomp) score += 1;
  if (noNewPrivsDisabled) score += 1;
  if (dangerousCaps) score += 2;
  else if (broadCaps) score += 1;
  // score range: 0-5
  const risk = processHardeningRisk(score);

  addNode(builder, {
    id: "runtime:process-security",
    label: "Process Security",
    type: "runtime",
    risk,
    tags,
    evidence: ["proc.status_security"],
    detail: { uid, seccomp, noNewPrivs, capabilities, score },
  });
  addEdge(builder, podNodeId, "runtime:process-security", "runs as", "runtime", risk, ["proc.status_security"]);
  addFinding(builder, {
    id: "escape-process-hardening-weak",
    title: "进程硬化信号偏弱",
    category: "escape",
    severity: risk,
    description: processHardeningDescription(root, noSeccomp, noNewPrivsDisabled, broadCaps, dangerousCaps, score),
    evidence: ["proc.status_security"],
    nodes: [podNodeId, "runtime:process-security"],
    templates: risk === "critical" || risk === "high" ? ["pod-privileged", "pod-hostpath"] : [],
    nextSteps: processHardeningNextSteps(risk),
  });
}

function hasDangerousCapability(effectiveCaps?: string): boolean {
  if (!effectiveCaps) return false;
  const eff = parseInt(effectiveCaps, 16);
  if (!Number.isFinite(eff)) return false;
  // CAP_SYS_ADMIN(21), CAP_SYS_MODULE(16), CAP_SYS_PTRACE(19), CAP_SYS_RAWIO(23)
  return [21, 16, 19, 23].some((bit) => (eff & (1 << bit)) !== 0);
}

function processHardeningRisk(score: number): RiskLevel {
  if (score >= 5) return "critical";
  if (score >= 3) return "high";
  if (score >= 2) return "medium";
  if (score >= 1) return "low";
  return "info";
}

function processHardeningDescription(
  root: boolean,
  noSeccomp: boolean,
  noNewPrivsDisabled: boolean,
  broadCaps: boolean,
  dangerousCaps: boolean,
  score: number,
): string {
  const signals: string[] = [];
  if (root) signals.push("uid=0(容器root)");
  if (noSeccomp) signals.push("seccomp 未启用");
  if (noNewPrivsDisabled) signals.push("no_new_privs 未设置(允许exec提权)");
  if (dangerousCaps) signals.push("携带高危 capability(SYS_ADMIN/SYS_MODULE/SYS_PTRACE/SYS_RAWIO)");
  else if (broadCaps) signals.push("携带非零 capability 集合");
  const riskLabel = score >= 5 ? "极弱" : score >= 3 ? "偏弱" : score >= 2 ? "中等" : "良好";
  return `进程硬化程度: ${riskLabel} (评分${score}/5)。${signals.length ? "观察信号: " + signals.join("; ") + "。" : ""}单独不能证明逃逸能力，但会放大 hostPath、privileged 或内核面的利用价值。`;
}

function processHardeningNextSteps(risk: RiskLevel): string[] {
  if (risk === "critical" || risk === "high") {
    return [
      "当前进程缺少多层加固。优先验证 seccomp/AppArmor/SELinux profile 是否已正确应用到容器。",
      "如果容器具备 hostPath 写权限，高危 capability 组合可能直接形成逃逸路径。",
    ];
  }
  if (risk === "medium") {
    return ["进程缺少部分加固层。结合容器实际 capability 解码和挂载点权限做受控验证。"];
  }
  return ["进程硬化状态良好，但仍需结合内核版本和挂载点做整体评估。"];
}

function addServiceAccountMaterial(builder: Builder, result: SanitizedResult, facts: Map<string, SanitizedFact>, serviceAccountNodeId: string): void {
  for (const fact of result.facts.filter((item) => item.id === "serviceaccount.mounted" || item.id === "environment.secret_like")) {
    const ref = factRef(fact);
    if (!ref) continue;
    const nodeId = `material:${fact.id}:${fact.source ?? ""}`;
    addNode(builder, {
      id: nodeId,
      label: fact.id === "environment.secret_like" ? "Environment secrets" : "Mounted SA material",
      type: "material",
      risk: "high",
      subtitle: fact.source,
      tags: ["sensitive", fact.collector],
      evidence: [fact.id],
      materialRef: ref,
    });
    addEdge(builder, serviceAccountNodeId, nodeId, "material", "secret", "high", [fact.id]);
  }
}

function addAuthorization(builder: Builder, result: SanitizedResult, facts: Map<string, SanitizedFact>, serviceAccountNodeId: string): boolean {
  let hasClusterAdmin = false;
  const access = arrayOfRecords(rawFactValue(result, facts.get("k8s_permissions.high_value_access")));
  const expandedAccess = arrayOfRecords(rawFactValue(result, facts.get("k8s_permissions.expanded_wildcards")));
  const allowed = access.filter((item) => item.allowed === true);
  const denied = access.filter((item) => item.allowed === false);
  const expandedAllowed = expandedAccess.filter((item) => item.allowed === true);
  const byId = new Map(access.map((item) => [stringValue(item.id) ?? "", item]));
  for (const item of allowed) {
    const id = stringValue(item.id) ?? "permission";
    const attrs = asRecord(item.resourceAttributes);
    const nodeId = `permission:${id}`;
    const severity = permissionRisk(id);
    addNode(builder, {
      id: nodeId,
      label: id.replaceAll("_", " "),
      type: "permission",
      risk: severity,
      subtitle: permissionSubtitle(attrs),
      tags: ["allowed", stringValue(attrs.verb) ?? "", resourceName(attrs)].filter(Boolean),
      evidence: ["k8s_permissions.high_value_access"],
      detail: { description: stringValue(item.description), reason: stringValue(item.reason), resourceAttributes: attrs },
    });
    addEdge(builder, serviceAccountNodeId, nodeId, "allowed", "rbac", severity, ["k8s_permissions.high_value_access"]);
  }

  if (expandedAccess.length) {
    const expansionNodeId = "permission:expanded-wildcards";
    addNode(builder, {
      id: expansionNodeId,
      label: "Expanded wildcard SSAR",
      type: "permission",
      risk: expandedAllowed.length ? "critical" : "blocked",
      tags: ["SSRR->SSAR", `${expandedAccess.length} checks`, `${expandedAllowed.length} allowed`],
      evidence: ["k8s_permissions.expanded_wildcards", "k8s_permissions.self_subject_rules"],
      detail: {
        total: expandedAccess.length,
        allowed: expandedAllowed.length,
        examples: expandedAccess.slice(0, 16),
      },
    });
    addEdge(builder, serviceAccountNodeId, expansionNodeId, "expanded", "rbac", expandedAllowed.length ? "critical" : "blocked", [
      "k8s_permissions.expanded_wildcards",
    ]);
  }

  for (const item of expandedAllowed) {
    const id = stringValue(item.id) ?? "expanded_permission";
    const attrs = asRecord(item.resourceAttributes);
    const nodeId = `permission:expanded:${id}`;
    const severity = expandedPermissionRisk(id, attrs);
    addNode(builder, {
      id: nodeId,
      label: `expanded ${stringValue(attrs.verb) ?? ""} ${resourceName(attrs)}`.trim(),
      type: "permission",
      risk: severity,
      subtitle: permissionSubtitle(attrs),
      tags: ["allowed", "expanded-wildcard", stringValue(attrs.verb) ?? "", resourceName(attrs)].filter(Boolean),
      evidence: ["k8s_permissions.expanded_wildcards"],
      detail: {
        id,
        description: stringValue(item.description),
        reason: stringValue(item.reason),
        expansionReason: stringValue(item.expansionReason),
        sourceRuleIndex: item.sourceRuleIndex,
        sourceRule: item.sourceRule,
        resourceAttributes: attrs,
      },
    });
    addEdge(builder, serviceAccountNodeId, nodeId, "wildcard allowed", "rbac", severity, ["k8s_permissions.expanded_wildcards"]);
  }

  const secretEvidence = access
    .filter((item) => item.allowed === true)
    .map((item) => stringValue(item.id))
    .filter((id): id is string => typeof id === "string" && id.includes("secrets") && (id.includes("_get") || id.includes("_list")));
  if (secretEvidence.length) {
    addFinding(builder, {
      id: "exploit-rbac-secret-read",
      title: "可读取命名空间 Secret",
      category: "material",
      severity: "critical",
      description: "SSAR 显示当前 ServiceAccount 可 get/list secrets。结合 permitted lists，页面可直接点开测试环境 Secret 查看原文。",
      evidence: [`k8s_permissions.high_value_access:${secretEvidence.join(",")}`, "k8s_objects.permitted_lists"],
      nodes: [serviceAccountNodeId, ...secretEvidence.map((id) => `permission:${id}`)],
      templates: ["secret-list-get-verify", "secret-material-review"],
      nextSteps: ["优先查看 service-account-token、registry auth、Opaque Secret，并把 blast radius 限定在 namespace scope。"],
    });
  }

  const workloadIds = access
    .filter((item) => item.allowed === true)
    .map((item) => stringValue(item.id))
    .filter((id): id is string =>
      typeof id === "string" &&
      (id.includes("pods_create") ||
        id === "jobs_create" ||
        id === "deployments_create" ||
        id === "cronjobs_create" ||
        id === "kube_system_pods_create"),
    );
  if (workloadIds.length) {
    addFinding(builder, {
      id: "exploit-rbac-workload-execution",
      title: "可创建工作负载获得执行能力",
      category: "exploit",
      severity: "high",
      description: "当前身份具备创建 Pod/Job/Deployment/CronJob 的部分能力。safe 结果不能证明 admission 会放行危险 PodSpec，但这是可验证的执行与持久化路径。",
      evidence: [`k8s_permissions.high_value_access:${workloadIds.join(",")}`],
      nodes: [serviceAccountNodeId, ...workloadIds.map((id) => `permission:${id}`)],
      templates: ["pod-create-job", "controller-persistence-review"],
      nextSteps: ["用 dry-run 或 full 模式验证 admission 是否允许 privileged、hostPath、hostNetwork 等 PodSpec。"],
    });
  }

  if (byId.get("pods_exec")?.allowed === true) {
    addFinding(builder, {
      id: "exploit-rbac-pods-exec",
      title: "可通过 pods/exec 横向进入 Pod",
      category: "exploit",
      severity: "high",
      description: "SSAR 显示 pods/exec create 允许。可用于同命名空间 Pod 内横向验证，具体目标应由业务授权范围和 Pod 价值决定。",
      evidence: ["k8s_permissions.high_value_access:pods_exec"],
      nodes: [serviceAccountNodeId, "permission:pods_exec"],
      templates: ["pods-exec-verify"],
      nextSteps: ["优先选择测试命名空间或授权目标 Pod，记录命令模板而不在 Web UI 自动执行。"],
    });
  }

  const clusterControlIds = allowed
    .map((item) => stringValue(item.id))
    .filter((id): id is string => typeof id === "string" && isClusterControlPermission(id));
  if (clusterControlIds.length) {
    addFinding(builder, {
      id: "exploit-rbac-cluster-control",
      title: "存在集群级控制面权限",
      category: "exploit",
      severity: "critical",
      description: "SSAR 显示当前 ServiceAccount 至少具备一项集群级或 kube-system 高危能力。若 webhook/ClusterRoleBinding/kube-system Pod 等返回 allowed:true，不需要先做容器逃逸即可进入集群控制面验证路径。",
      evidence: [`k8s_permissions.high_value_access:${clusterControlIds.join(",")}`],
      nodes: [serviceAccountNodeId, ...clusterControlIds.map((id) => `permission:${id}`)],
      templates: ["rbac-bind-escalate-verify", "admission-policy-governance", "pod-create-job", "secret-list-get-verify"],
      nextSteps: ["优先确认 allowed:true 的具体 ID、scope 和 reason；只生成 dry-run/计划模板，不在 Web UI 自动修改 webhook 或 RBAC。"],
    });
  }

  const expandedAllowedIds = expandedAllowed.map((item) => stringValue(item.id)).filter((id): id is string => typeof id === "string");
  if (expandedAccess.length) {
    const allowedNodes = expandedAllowedIds.map((id) => `permission:expanded:${id}`);
    addFinding(builder, {
      id: expandedAllowedIds.length ? "exploit-rbac-expanded-wildcards" : "blocked-rbac-expanded-wildcards",
      title: expandedAllowedIds.length ? "wildcard 展开后存在真实 allowed 裁决" : "wildcard 展开后未发现高危 allowed 裁决",
      category: expandedAllowedIds.length ? "exploit" : "blocked",
      severity: expandedAllowedIds.length ? "critical" : "blocked",
      description: expandedAllowedIds.length
        ? "k8s_permissions.expanded_wildcards 将 SSRR wildcard rule 展开为高危 verb/resource 的 SSAR，并确认其中存在 allowed:true。平台 CRD 的真实威力应以这些裁决为准。"
        : "k8s_permissions.expanded_wildcards 已执行 SSRR wildcard 展开，但本轮高危候选 SSAR 没有 returned allowed:true。",
      evidence: ["k8s_permissions.expanded_wildcards", "k8s_permissions.self_subject_rules"],
      nodes: ["permission:expanded-wildcards", ...allowedNodes.slice(0, 24)],
      templates: ["operator-crd-controller-abuse", "controller-persistence-review", "rbac-bind-escalate-verify", "admission-policy-governance"],
      nextSteps: expandedAllowedIds.length
        ? ["优先查看 expanded permission 节点中的 sourceRule 和 reason，按平台 CRD 控制器副作用确认是否能创建/修改实际工作负载。"]
        : ["保留 SSRR wildcard 作为背景风险；如果角色或 namespace 变化，重新采集后再看 expanded_wildcards。"],
    });
  }

  const blockedIds = denied.map((item) => stringValue(item.id)).filter((id): id is string => Boolean(id));
  const importantBlocked = blockedIds.filter((id) => id.includes("nodes_proxy") || id.includes("role") || id.includes("impersonate") || id.includes("ephemeralcontainers"));
  if (importantBlocked.length) {
    const nodeId = "permission:blocked-high-value";
    addNode(builder, {
      id: nodeId,
      label: "Blocked high-value API",
      type: "permission",
      risk: "blocked",
      tags: ["denied", `${importantBlocked.length} checks`],
      evidence: ["k8s_permissions.high_value_access"],
      detail: { denied: importantBlocked },
    });
    addEdge(builder, serviceAccountNodeId, nodeId, "denied", "rbac", "blocked", ["k8s_permissions.high_value_access"]);
    addFinding(builder, {
      id: "blocked-rbac-escalation-node",
      title: "RBAC 直接提权和 nodes/proxy 路径受阻",
      category: "blocked",
      severity: "blocked",
      description: "role/clusterrole bind/escalate、impersonate、nodes/proxy、ephemeralcontainers 等高价值 API 在本次 SSAR 中未允许。",
      evidence: [`k8s_permissions.high_value_access:${importantBlocked.join(",")}`],
      nodes: [serviceAccountNodeId, nodeId],
      templates: ["nodes-proxy-verify", "impersonate-verify", "rbac-bind-escalate-verify", "ephemeralcontainers-patch"],
      nextSteps: ["保留为受阻路径，不把它们标成可利用；如果角色变化，重新跑采集。"],
    });
  }

  const rules = asRecord(rawFactValue(result, facts.get("k8s_permissions.self_subject_rules")));
  const resourceRules = arrayOfRecords(rules.resourceRules);
  const wildcardRules = resourceRules.filter((rule) => arrayOfStrings(rule.verbs).includes("*") || arrayOfStrings(rule.resources).includes("*"));
  if (wildcardRules.length) {
    const nodeId = "permission:wildcard-rules";
    addNode(builder, {
      id: nodeId,
      label: "Wildcard RBAC rules",
      type: "permission",
      risk: "high",
      tags: ["SSRR", `${wildcardRules.length} wildcard rules`],
      evidence: ["k8s_permissions.self_subject_rules"],
      detail: { examples: wildcardRules.slice(0, 12) },
    });
    addEdge(builder, serviceAccountNodeId, nodeId, "SSRR", "rbac", "high", ["k8s_permissions.self_subject_rules"]);
    addFinding(builder, {
      id: "exploit-rbac-wildcard-rules",
      title: "SSRR 暴露多条 wildcard 授权",
      category: "exploit",
      severity: "high",
      description: "SelfSubjectRulesReview 中存在 wildcard verb/resource，覆盖多个平台 CRD 和控制器资源。实际影响需结合 namespaced scope 与 admission/controller 行为判断。",
      evidence: ["k8s_permissions.self_subject_rules"],
      nodes: [serviceAccountNodeId, nodeId],
      templates: ["operator-crd-controller-abuse", "controller-persistence-review"],
      nextSteps: ["优先分析平台自定义 Job、Notebook、Kubeflow、admissionregistration 等 CRD 的控制器副作用。"],
    });
    if (detectClusterAdminFromRules(wildcardRules)) {
      hasClusterAdmin = true;
    }
  }

  // Fallback: detect cluster-admin from high-value access (all critical checks allowed)
  if (!hasClusterAdmin && allowed.length >= 6) {
    const clusterControlAllowed = allowed.filter((item) => {
      const id = stringValue(item.id) ?? "";
      return isClusterControlPermission(id) || id.includes("secrets") || id.includes("pods_exec") || id.includes("pods_create");
    });
    const totalAvailable = access.filter((item) => {
      const id = stringValue(item.id) ?? "";
      return isClusterControlPermission(id) || id.includes("secrets");
    }).length;
    if (clusterControlAllowed.length >= 5 && clusterControlAllowed.length === totalAvailable) {
      const hasStarVerbs = wildcardRules.some((rule) =>
        arrayOfStrings(rule.verbs).includes("*") && arrayOfStrings(rule.resources).includes("*")
      );
      if (hasStarVerbs) hasClusterAdmin = true;
    }
  }

  return hasClusterAdmin;
}

function addPermittedObjects(
  builder: Builder,
  result: SanitizedResult,
  facts: Map<string, SanitizedFact>,
  namespaceNodeId: string,
  currentServiceAccountNodeId: string,
  currentPodNodeId: string,
  currentNamespace?: string,
  currentPodName?: string,
): void {
  const permitted = asRecord(rawFactValue(result, facts.get("k8s_objects.permitted_lists")));
  const items = arrayOfRecords(permitted.items);
  const secretRecords = collectSecrets(items);
  const secretByKey = new Map(secretRecords.map((secret) => [`${secret.namespace}/${secret.name}`, secret]));

  for (const item of items) {
    const kind = stringValue(item.kind) ?? "Resource";
    const resource = stringValue(item.resource) ?? kind.toLowerCase();
    const groupVersion = stringValue(item.groupVersion) ?? "";
    const list = asRecord(item.list);
    const objects = arrayOfRecords(list.items);
    const resourceNodeId = `resource:${groupVersion}/${resource}`;
    addNode(builder, {
      id: resourceNodeId,
      label: `${kind} x${objects.length}`,
      type: "resource",
      risk: resourceRisk(resource, kind),
      subtitle: groupVersion,
      tags: [resource, stringValue(item.namespace) ?? ""].filter(Boolean),
      evidence: ["k8s_objects.permitted_lists"],
      detail: { groupVersion, kind, resource, namespace: stringValue(item.namespace), count: objects.length },
    });
    addEdge(builder, namespaceNodeId, resourceNodeId, "listed", "inventory", resourceRisk(resource, kind), ["k8s_objects.permitted_lists"]);

    if (kind === "Secret") {
      for (const secret of secretRecords) {
        addSecretNode(builder, secret);
        addEdge(builder, resourceNodeId, secretId(secret.namespace, secret.name), secret.type, "secret", secret.type.includes("service-account-token") ? "critical" : "high", [
          "k8s_objects.permitted_lists",
        ]);
      }
      continue;
    }

    if (kind === "ServiceAccount") {
      for (const object of objects) {
        const meta = asRecord(object.metadata);
        const namespace = stringValue(meta.namespace) ?? currentNamespace ?? "";
        const name = stringValue(meta.name);
        if (!name || !namespace) continue;
        const saNodeId = serviceAccountId(namespace, name);
        addNode(builder, {
          id: saNodeId,
          label: name,
          type: "serviceaccount",
          risk: name === "default" ? "high" : "low",
          subtitle: namespace,
          tags: ["enumerated"],
          evidence: ["k8s_objects.permitted_lists"],
          detail: { namespace, name },
        });
        addEdge(builder, namespaceNodeId, saNodeId, "serviceaccount", "inventory", name === "default" ? "medium" : "low", ["k8s_objects.permitted_lists"]);
        for (const ref of arrayOfRecords(object.secrets)) {
          const secretName = stringValue(ref.name);
          if (!secretName) continue;
          const secret = secretByKey.get(`${namespace}/${secretName}`);
          if (secret) addSecretNode(builder, secret);
          addEdge(builder, saNodeId, secretId(namespace, secretName), "token secret", "secret", "critical", ["k8s_objects.permitted_lists"]);
        }
      }
      continue;
    }

    if (kind === "Pod") {
      for (const object of objects) {
        const meta = asRecord(object.metadata);
        const spec = asRecord(object.spec);
        const namespace = stringValue(meta.namespace) ?? currentNamespace ?? "";
        const name = stringValue(meta.name);
        if (!name || !namespace) continue;
        const id = podId(namespace, name);
        const podRisk = discoveredPodRisk(spec, currentPodName === name);
        const tags = discoveredPodTags(spec, currentPodName === name);
        addNode(builder, {
          id,
          label: name,
          type: "pod",
          risk: podRisk,
          subtitle: `${namespace} / ${stringValue(spec.serviceAccountName) ?? "default"}`,
          tags,
          evidence: ["k8s_objects.permitted_lists"],
          detail: podInventoryDetail(spec),
        });
        addEdge(builder, resourceNodeId, id, "pod", "inventory", podRisk, ["k8s_objects.permitted_lists"]);
        const sa = stringValue(spec.serviceAccountName) ?? "default";
        addEdge(builder, id, serviceAccountId(namespace, sa), "uses", "identity", "medium", ["k8s_objects.permitted_lists"]);
        if (currentPodName === name) {
          addEdge(builder, currentPodNodeId, id, "same pod", "identity", "info", ["k8s_objects.permitted_lists"]);
        }
      }
    }
  }

  if (secretRecords.length) {
    addFinding(builder, {
      id: "material-secret-inventory",
      title: "可枚举 Secret 清单并定位 token",
      category: "material",
      severity: "critical",
      description: `permitted lists 中包含 ${secretRecords.length} 个 Secret，其中 ${secretRecords.filter((item) => item.type.includes("service-account-token")).length} 个是 ServiceAccount token 类型。`,
      evidence: ["k8s_objects.permitted_lists"],
      nodes: [currentServiceAccountNodeId, ...secretRecords.slice(0, 12).map((item) => secretId(item.namespace, item.name))],
      templates: ["secret-material-review", "secret-list-get-verify"],
      nextSteps: ["点击 Secret 节点查看测试环境材料；优先比对 token 对应 ServiceAccount 与 RBAC 权限。"],
    });
  }
}

function addCollectionErrors(builder: Builder, result: SanitizedResult): void {
  if (!result.errors.length) return;
  addNode(builder, {
    id: "collector:errors",
    label: "Collector errors",
    type: "context",
    risk: "unknown",
    tags: [`${result.errors.length} errors`],
    evidence: ["errors"],
    detail: { count: result.errors.length, examples: result.errors.slice(0, 8) },
  });
  addFinding(builder, {
    id: "context-partial-collection",
    title: "采集结果包含部分失败",
    category: "context",
    severity: "unknown",
    description: "本次 safe 模式有 collector/API 错误，图谱仅代表已采集事实；未采到不等于不存在。",
    evidence: ["errors"],
    nodes: ["collector:errors"],
    templates: [],
    nextSteps: ["对关键未知项使用 full 模式或定向 collector 复测。"],
  });
}

function addCompoundFindings(builder: Builder): void {
  const existingIds = new Set(Array.from(builder.findings.values()).map((f) => f.id));

  // Detect hostPID + dangerous capability combination (SYS_PTRACE/SYS_ADMIN enables host process injection)
  const hasHostPID = builder.findings.has("document:escape-host-pid-namespace-shared") ||
    Array.from(builder.findings.values()).some((f) => f.title.includes("hostPID") || f.title.includes("Host PID"));
  const processNode = builder.nodes.get("runtime:process-security");
  const processHasDangerousCaps = processNode?.tags.some((t) => t === "dangerous-caps") ?? false;
  if (hasHostPID && processHasDangerousCaps && !existingIds.has("compound-hostpid-dangerous-caps")) {
    addFinding(builder, {
      id: "compound-hostpid-dangerous-caps",
      title: "hostPID + 高危 Capability 可注入宿主机进程",
      category: "escape",
      severity: "critical",
      confidence: "probable",
      description: "当前容器共享宿主机 PID 命名空间，同时携带高危 capability（SYS_PTRACE/SYS_ADMIN/SYS_MODULE/SYS_RAWIO）。此组合允许直接 ptrace 注入宿主机进程（kubelet/containerd 等），达成容器逃逸。",
      evidence: ["proc.namespaces_self", "proc.namespaces_pid1", "proc.status_security"],
      nodes: ["runtime:process-security", podNodeIdFromFindings(builder)].filter(Boolean),
      templates: ["pod-hostpid", "pod-privileged"],
      nextSteps: [
        "确认宿主机可见进程列表（ps aux 或 /proc 遍历）。",
        "验证 ptrace 是否被 seccomp/YAMA 阻止（/proc/sys/kernel/yama/ptrace_scope）。",
        "优先选择 kubelet/containerd 进程作为注入目标。",
      ],
      origin: "graph",
    });
  }

  // Detect SA token mounted + secrets list/get capability
  const hasSAToken = builder.findings.has("material-mounted-serviceaccount-token");
  const hasSecretRead = builder.findings.has("exploit-rbac-secret-read");
  if (hasSAToken && hasSecretRead && !existingIds.has("compound-sa-token-secret-read")) {
    addFinding(builder, {
      id: "compound-sa-token-secret-read",
      title: "SA Token + Secret 读取权限可窃取命名空间所有凭证",
      category: "material",
      severity: "critical",
      confidence: "probable",
      description: "当前 ServiceAccount token 已挂载，同时具备 secrets get/list 权限。可直接通过 Kubernetes API 拉取同命名空间内所有 Secret（含其他 SA token、registry auth、Opaque 凭证），无需额外逃逸即可大规模横向移动。",
      evidence: ["serviceaccount.mounted", "k8s_permissions.high_value_access"],
      nodes: Array.from(builder.nodes.keys()).filter((id) => id.startsWith("serviceaccount:") || id.startsWith("permission:") || id.startsWith("secret:")).slice(0, 12),
      templates: ["secret-list-get-verify", "serviceaccount-token-api-verify"],
      nextSteps: [
        "使用当前 SA token 直接执行 kubectl get secrets -o yaml 验证 blast radius。",
        "重点复核 kube-system 命名空间和跨命名空间 Secret 可读性。",
      ],
      origin: "graph",
    });
  }

  // Detect pods/exec + discovered privileged pod in the same namespace
  const hasPodsExec = builder.findings.has("exploit-rbac-pods-exec");
  const privilegedPodIds = Array.from(builder.nodes.values())
    .filter((n) => n.type === "pod" && n.risk === "critical" && n.tags.includes("privileged"))
    .map((n) => n.id);
  if (hasPodsExec && privilegedPodIds.length > 0 && !existingIds.has("compound-pods-exec-privileged-pod")) {
    addFinding(builder, {
      id: "compound-pods-exec-privileged-pod",
      title: "可通过 pods/exec 横向移动到 Privileged Pod 完成逃逸",
      category: "exploit",
      severity: "critical",
      confidence: "probable",
      description: `当前身份具备 pods/exec 权限，且同命名空间内发现 ${privilegedPodIds.length} 个 privileged Pod。进入 privileged 容器后可直接挂载宿主机文件系统或使用其他特权达成逃逸，无需经过内核 LPE。`,
      evidence: ["k8s_permissions.high_value_access:pods_exec", "k8s_objects.permitted_lists"],
      nodes: [podNodeIdFromFindings(builder), ...privilegedPodIds.slice(0, 3)].filter(Boolean),
      templates: ["pods-exec-verify", "pod-privileged"],
      nextSteps: [
        "确认目标 privileged Pod 的 securityContext 和挂载卷。",
        "验证 admission webhook 不会阻止 exec 操作。",
        "生成 safe 模式的 kubectl exec 命令模板，不自动执行。",
      ],
      origin: "graph",
    });
  }

  // Detect writable hostPath to dangerous directory + write-capable process
  const criticalHostPathNodes = Array.from(builder.nodes.values())
    .filter((n) => n.type === "hostpath" && (n.risk === "critical" || n.risk === "high"))
    .map((n) => ({ id: n.id, label: n.label, risk: n.risk }));
  const processCanWrite = processNode && (processHasDangerousCaps || processNode.tags.includes("uid=0"));
  if (criticalHostPathNodes.length > 0 && processCanWrite && !existingIds.has("compound-hostpath-dangerous-write")) {
    addFinding(builder, {
      id: "compound-hostpath-dangerous-write",
      title: "高危 hostPath 可写 + 特权进程 → 可直接修改宿主机文件",
      category: "escape",
      severity: "critical",
      confidence: "probable",
      description: `发现 ${criticalHostPathNodes.length} 个高危 hostPath 挂载点（${criticalHostPathNodes.map((n) => n.label).join(", ")}），且当前进程具备写入能力（root 用户或高危 capability）。可直接覆写宿主机关键文件达成持久化或逃逸。`,
      evidence: ["k8s_profile.current_pod_structured", "proc.status_security", "filesystem.volume_hints"],
      nodes: ["runtime:process-security", podNodeIdFromFindings(builder), ...criticalHostPathNodes.map((n) => n.id).slice(0, 4)].filter(Boolean),
      templates: ["pod-hostpath"],
      nextSteps: [
        "在文件系统中确认 mount 的实际读写权限（touch 测试）。",
        "注意 mount 的 readOnly 标志和 hostPath type（DirectoryOrCreate 等）。",
      ],
      origin: "graph",
    });
  }
}

function podNodeIdFromFindings(builder: Builder): string {
  return Array.from(builder.nodes.keys()).find((id) => id.startsWith("pod:") && !id.includes("/")) ?? "";
}

function addSecretNode(builder: Builder, secret: SecretRecord): void {
  const token = secret.type.includes("service-account-token");
  addNode(builder, {
    id: secretId(secret.namespace, secret.name),
    label: secret.name,
    type: "secret",
    risk: token ? "critical" : "high",
    subtitle: `${secret.namespace} / ${secret.type}`,
    tags: [token ? "service-account-token" : secret.type, "clickable"].filter(Boolean),
    evidence: ["k8s_objects.permitted_lists"],
    materialRef: secretRef(secret.namespace, secret.name),
    detail: {
      namespace: secret.namespace,
      type: secret.type,
      dataKeys: Object.keys(asRecord(secret.item.data)),
    },
  });
}

function collectSecrets(items: Record<string, unknown>[]): SecretRecord[] {
  const out: SecretRecord[] = [];
  for (const item of items) {
    if (stringValue(item.kind) !== "Secret") continue;
    const list = asRecord(item.list);
    for (const object of arrayOfRecords(list.items)) {
      const meta = asRecord(object.metadata);
      const namespace = stringValue(meta.namespace);
      const name = stringValue(meta.name);
      if (!namespace || !name) continue;
      out.push({ namespace, name, type: stringValue(object.type) ?? "Opaque", item: object });
    }
  }
  return out;
}

function findSecret(result: SanitizedResult, namespace: string, name: string): SecretRecord | undefined {
  const permittedFact = result.facts.find((fact) => fact.id === "k8s_objects.permitted_lists");
  const permitted = asRecord(rawFactValue(result, permittedFact));
  return collectSecrets(arrayOfRecords(permitted.items)).find((secret) => secret.namespace === namespace && secret.name === name);
}

function withDecodedSecretData(secret: Record<string, unknown>): Record<string, unknown> {
  const data = asRecord(secret.data);
  const decodedData: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value !== "string") continue;
    decodedData[key] = decodeBase64ForDisplay(value);
  }
  return { ...secret, decodedData };
}

function decodeBase64ForDisplay(value: string): unknown {
  try {
    const buffer = Buffer.from(value, "base64");
    if (buffer.length > 65536) {
      return { bytes: buffer.length, note: "value too large to decode in UI" };
    }
    const text = buffer.toString("utf8");
    const printable = /^[\t\r\n\x20-\x7e\u0080-\ufffd]*$/u.test(text);
    return printable ? text : { bytes: buffer.length, base64: value };
  } catch {
    return { decodeError: true, base64: value };
  }
}

function calculateStats(builder: Builder): Record<string, number> {
  const stats: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    escapeFindings: 0,
    exploitFindings: 0,
    lpeFindings: 0,
    materialFindings: 0,
    secretNodes: 0,
  };
  for (const node of builder.nodes.values()) {
    if (node.risk === "critical") stats.critical++;
    if (node.risk === "high") stats.high++;
    if (node.risk === "medium") stats.medium++;
    if (node.type === "secret") stats.secretNodes++;
  }
  for (const finding of builder.findings.values()) {
    if (finding.category === "escape") stats.escapeFindings++;
    if (finding.category === "exploit") stats.exploitFindings++;
    if (finding.category === "lpe") stats.lpeFindings++;
    if (finding.category === "material") stats.materialFindings++;
  }
  return stats;
}

function addNode(builder: Builder, node: GraphNode): void {
  const current = builder.nodes.get(node.id);
  if (!current) {
    builder.nodes.set(node.id, { ...node, tags: unique(node.tags), evidence: unique(node.evidence) });
    return;
  }
  current.risk = maxRisk(current.risk, node.risk);
  current.tags = unique([...current.tags, ...node.tags]);
  current.evidence = unique([...current.evidence, ...node.evidence]);
  current.materialRef ??= node.materialRef;
  current.subtitle ??= node.subtitle;
  current.detail = { ...(current.detail ?? {}), ...(node.detail ?? {}) };
}

function addEdge(builder: Builder, from: string, to: string, label: string, type: string, risk: RiskLevel, evidence: string[]): void {
  const id = `${from}->${to}:${type}:${label}`;
  if (builder.edges.has(id)) return;
  builder.edges.set(id, { id, from, to, label, type, risk, evidence });
}

function addFinding(builder: Builder, finding: GraphFinding): void {
  const current = builder.findings.get(finding.id);
  if (!current) {
    builder.findings.set(finding.id, { ...finding, evidence: unique(finding.evidence), nodes: unique(finding.nodes) });
    return;
  }
  current.severity = maxRisk(current.severity, finding.severity);
  current.evidence = unique([...current.evidence, ...finding.evidence]);
  current.nodes = unique([...current.nodes, ...finding.nodes]);
  current.templates = unique([...current.templates, ...finding.templates]);
  current.nextSteps = unique([...current.nextSteps, ...finding.nextSteps]);
  current.origin ??= finding.origin;
  current.confidence ??= finding.confidence;
  current.expParams ??= finding.expParams;
}

function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return riskRank[b] > riskRank[a] ? b : a;
}

function rawFactValue(result: SanitizedResult, fact?: SanitizedFact): unknown {
  if (!fact) return undefined;
  const ref = factRef(fact);
  return ref ? result.sensitiveMaterial.get(ref) ?? fact.value : fact.value;
}

function factRef(fact: SanitizedFact): string | undefined {
  const value = asRecord(fact.value);
  return stringValue(value.ref);
}

function scoreHostPath(path: string): RiskLevel {
  if (path === "/" || path.startsWith("/var/lib/kubelet") || path.startsWith("/var/run") || path.startsWith("/run")) return "critical";
  if (path.includes("containerd") || path.includes("pouch") || path.startsWith("/etc") || path.startsWith("/proc") || path.startsWith("/sys")) return "high";
  return "medium";
}

function permissionRisk(id: string): RiskLevel {
  if (isClusterControlPermission(id)) return "critical";
  if (id.includes("secrets")) return "critical";
  if (id.includes("pods_exec") || id.includes("pods_attach")) return "high";
  if (id.includes("pods_create") || id.includes("deployments_create") || id.includes("jobs_create") || id.includes("daemonsets_create")) return "medium";
  if (id.includes("persistentvolumeclaims") || id.includes("configmaps")) return "medium";
  if (id.includes("pods_log") || id.includes("pods_list") || id.includes("serviceaccounts_list")) return "low";
  return "info";
}

function expandedPermissionRisk(id: string, attrs: Record<string, unknown>): RiskLevel {
  const namespace = stringValue(attrs.namespace);
  const group = stringValue(attrs.group) ?? "";
  const resource = resourceName(attrs);
  if (namespace === "kube-system") return "critical";
  if (isExpandedClusterControl(group, resource)) return "critical";
  if (isPlatformAPIGroup(group)) return "critical";
  return permissionRisk(id);
}

function isClusterControlPermission(id: string): boolean {
  return (
    id === "clusterrolebindings_create" ||
    id === "clusterroles_bind" ||
    id === "clusterroles_escalate" ||
    id === "crd_create" ||
    id === "crd_patch" ||
    id.startsWith("mutatingwebhook_") ||
    id.startsWith("validatingwebhook_") ||
    id === "storageclass_create" ||
    id === "nodes_create" ||
    id === "nodes_patch" ||
    id === "csr_approve" ||
    id === "kube_system_pods_create" ||
    id === "kube_system_secrets_get" ||
    id === "kube_system_secrets_list"
  );
}

function isExpandedClusterControl(group: string, resource: string): boolean {
  return (
    group === "apiextensions.k8s.io" ||
    group === "admissionregistration.k8s.io" ||
    group === "storage.k8s.io" ||
    group === "certificates.k8s.io" ||
    resource === "nodes" ||
    resource === "nodes/proxy" ||
    resource === "namespaces" ||
    resource === "persistentvolumes" ||
    resource === "clusterroles" ||
    resource === "clusterrolebindings" ||
    resource.includes("secrets") ||
    resource.includes("serviceaccounts/token")
  );
}

function isPlatformAPIGroup(group: string): boolean {
  return Boolean(group) && !["apps", "batch", "rbac.authorization.k8s.io", "apiextensions.k8s.io", "admissionregistration.k8s.io", "storage.k8s.io", "certificates.k8s.io", "authorization.k8s.io", "coordination.k8s.io", "networking.k8s.io", "extensions"].includes(group);
}

function resourceRisk(resource: string, kind: string): RiskLevel {
  const value = `${resource} ${kind}`.toLowerCase();
  if (value.includes("secret")) return "critical";
  // listing pods/workloads is visibility, not operational capability
  if (value.includes("pod") || value.includes("deployment") || value.includes("workflow") || value.includes("job")) return "medium";
  // listing serviceaccounts is low-value without token material
  if (value.includes("serviceaccount")) return "low";
  return "info";
}

function discoveredPodRisk(spec: Record<string, unknown>, current: boolean): RiskLevel {
  if (current) return "critical";
  const privileged = arrayOfRecords(spec.containers).some((container) => asRecord(container.securityContext).privileged === true);
  if (privileged) return "critical";
  const hostPaths = arrayOfRecords(spec.volumes).filter((volume) => Object.keys(asRecord(volume.hostPath)).length > 0);
  if (hostPaths.length) return "high";
  // discovered pods are relevant lateral-movement targets even without obvious escape signals
  return "low";
}

function discoveredPodTags(spec: Record<string, unknown>, current: boolean): string[] {
  const tags = current ? ["current"] : ["enumerated"];
  const privileged = arrayOfRecords(spec.containers).some((container) => asRecord(container.securityContext).privileged === true);
  const hostPathCount = arrayOfRecords(spec.volumes).filter((volume) => Object.keys(asRecord(volume.hostPath)).length > 0).length;
  if (privileged) tags.push("privileged");
  if (hostPathCount) tags.push(`${hostPathCount} hostPath`);
  return tags;
}

function podInventoryDetail(spec: Record<string, unknown>): Record<string, unknown> {
  return {
    serviceAccountName: stringValue(spec.serviceAccountName),
    nodeName: stringValue(spec.nodeName),
    hostNetwork: spec.hostNetwork === true,
    hostPID: spec.hostPID === true,
    hostIPC: spec.hostIPC === true,
    containers: arrayOfRecords(spec.containers).map((container) => ({
      name: stringValue(container.name),
      image: stringValue(container.image),
      privileged: asRecord(container.securityContext).privileged === true,
    })),
    hostPaths: arrayOfRecords(spec.volumes)
      .map((volume) => stringValue(asRecord(volume.hostPath).path))
      .filter(Boolean),
  };
}

function permissionSubtitle(attrs: Record<string, unknown>): string {
  const group = stringValue(attrs.group) ?? "";
  const resource = resourceName(attrs);
  const verb = stringValue(attrs.verb) ?? "";
  const namespace = stringValue(attrs.namespace);
  return `${verb} ${group ? `${group}/` : ""}${resource}${namespace ? ` in ${namespace}` : ""}`;
}

function resourceName(attrs: Record<string, unknown>): string {
  const resource = stringValue(attrs.resource) ?? "";
  const subresource = stringValue(attrs.subresource);
  return subresource ? `${resource}/${subresource}` : resource;
}

function normalizeRisk(value: unknown): RiskLevel {
  const risk = String(value ?? "").toLowerCase();
  if (risk === "critical" || risk === "high" || risk === "medium" || risk === "low" || risk === "info" || risk === "blocked" || risk === "unknown") {
    return risk;
  }
  return "unknown";
}

function splitEvidence(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  return String(value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stableId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5_.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 96) || "finding";
}

function podId(namespace: string, name: string): string {
  return `pod:${namespace}/${name}`;
}

function serviceAccountId(namespace: string, name: string): string {
  return `serviceaccount:${namespace}/${name}`;
}

function secretId(namespace: string, name: string): string {
  return `secret:${namespace}/${name}`;
}

function hostPathId(path: string): string {
  return `hostpath:${encodeURIComponent(path)}`;
}

function secretRef(namespace: string, name: string): string {
  return `sensitive://k8s-secret/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function arrayOfRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function detectClusterAdminFromRules(wildcardRules: Record<string, unknown>[]): boolean {
  for (const rule of wildcardRules) {
    const verbs = arrayOfStrings(rule.verbs);
    const resources = arrayOfStrings(rule.resources);
    const apiGroups = arrayOfStrings(rule.apiGroups);
    if (
      verbs.includes("*") &&
      resources.includes("*") &&
      (apiGroups.length === 0 || apiGroups.includes("*"))
    ) {
      return true;
    }
    // Also detect if all critical resources are covered by wildcard verbs
    if (verbs.includes("*") && resources.includes("*") && apiGroups.some((g) => g === "*" || g === "")) {
      return true;
    }
  }
  return false;
}

function addClusterAdminFinding(
  builder: Builder,
  serviceAccountNodeId: string,
  namespace?: string,
  serviceAccount?: string,
  podName?: string,
): void {
  const saLabel = namespace && serviceAccount
    ? `${namespace}:${serviceAccount}`
    : serviceAccount || "current ServiceAccount";
  addFinding(builder, {
    id: "cluster-admin-achieved",
    title: "已获得整个集群管理权限",
    category: "exploit",
    severity: "critical",
    confidence: "confirmed",
    description: `当前身份 ${saLabel}${podName ? `（Pod: ${podName}）` : ""} 具备集群管理员等效权限（*/*/*），已实质上控制整个 Kubernetes 集群。无需执行容器逃逸或权限提升，可直接操作任意命名空间中的任意资源。`,
    evidence: [
      "k8s_permissions.self_subject_rules",
      "k8s_permissions.high_value_access",
    ],
    nodes: [serviceAccountNodeId],
    templates: [],
    nextSteps: [],
    origin: "graph",
  });
}
