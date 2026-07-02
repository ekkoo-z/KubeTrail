export const allSkillNames = [
  "admission-policy-governance",
  "cloud-metadata-analysis",
  "exp-generation",
  "exposed-management-interfaces",
  "image-registry-supply-chain",
  "k8s-rbac-analysis",
  "kubelet-runtime-etcd-bypass",
  "network-lateral-movement",
  "observability-defense-evasion",
  "operator-crd-controller-abuse",
  "pod-escape-surface",
  "public-workload-rce-surface",
  "resource-hijack-dos",
  "service-ingress-exposure",
  "serviceaccount-secret-material",
  "windows-container-surface",
  "workload-controller-persistence",
] as const;

export type SkillName = typeof allSkillNames[number];

const allSkillNameSet = new Set<string>(allSkillNames);

export const coreAttackSkillNames: readonly SkillName[] = [
  "k8s-rbac-analysis",
  "serviceaccount-secret-material",
  "pod-escape-surface",
  "exp-generation",
  "kubelet-runtime-etcd-bypass",
];

const keywordSkills: Array<{ skills: readonly SkillName[]; patterns: RegExp[] }> = [
  {
    skills: ["cloud-metadata-analysis"],
    patterns: [/云身份|云元数据|metadata|imds|irsa|pod identity|workload identity|aws|azure|gcp|aliyun|sts/i],
  },
  {
    skills: ["network-lateral-movement"],
    patterns: [/横向|东西向|网络策略|networkpolicy|egress|dns|service mesh|istio|linkerd|cni|内网|侧向/i],
  },
  {
    skills: ["service-ingress-exposure"],
    patterns: [/ingress|gateway|nodeport|loadbalancer|externalip|externalname|hostport|service 暴露|公网|入口流量/i],
  },
  {
    skills: ["exposed-management-interfaces"],
    patterns: [/dashboard|kubeflow|argo\s*cd|rancher|prometheus|grafana|jupyter|airflow|jenkins|harbor|管理界面|控制台/i],
  },
  {
    skills: ["image-registry-supply-chain"],
    patterns: [/镜像|registry|imagepullsecret|pull secret|dockerconfig|sbom|supply chain|供应链|ci\/cd|github actions|gitlab/i],
  },
  {
    skills: ["admission-policy-governance"],
    patterns: [/admission|pod security|psa|gatekeeper|kyverno|webhook|validating|mutating|准入|策略引擎|资源配额|limitrange/i],
  },
  {
    skills: ["operator-crd-controller-abuse"],
    patterns: [/operator|crd|customresource|自定义资源|控制器滥用|reconcile|controller rbac/i],
  },
  {
    skills: ["workload-controller-persistence"],
    patterns: [/持久化|persistence|daemonset|deployment|statefulset|replicaset|cronjob|job|static pod|sidecar|init container/i],
  },
  {
    skills: ["observability-defense-evasion"],
    patterns: [/观测|审计|日志|defense evasion|audit|events?\b|runtime security|falco|检测绕过|清日志/i],
  },
  {
    skills: ["resource-hijack-dos"],
    patterns: [/dos|denial|挖矿|cryptomining|miner|quota|hpa|vpa|autoscaler|gpu|资源滥用|成本/i],
  },
  {
    skills: ["windows-container-surface"],
    patterns: [/windows|hostprocess|hyper-v|iis|powershell|win32/i],
  },
  {
    skills: ["public-workload-rce-surface"],
    patterns: [/rce|cve|漏洞利用|远程代码|webshell|公开服务|应用漏洞|exposed workload/i],
  },
];

export function resolveEnabledSkillNames(message: string, explicitSkills?: readonly string[]): SkillName[] {
  const selected = new Set<SkillName>();
  const requested = explicitSkills?.length ? explicitSkills : extractExplicitSkillNames(message);

  if (requestsAllSkills(message, requested)) {
    return [...allSkillNames];
  }

  for (const skill of coreAttackSkillNames) {
    selected.add(skill);
  }

  for (const skill of requested) {
    if (isKnownSkillName(skill)) {
      selected.add(skill);
    }
  }

  for (const entry of keywordSkills) {
    if (entry.patterns.some((pattern) => pattern.test(message))) {
      for (const skill of entry.skills) {
        selected.add(skill);
      }
    }
  }

  return [...allSkillNames].filter((name) => selected.has(name));
}

function extractExplicitSkillNames(message: string): string[] {
  const names = new Set<string>();
  for (const match of message.matchAll(/\bSkill\s*:\s*([A-Za-z0-9_-]{1,80})/gi)) {
    names.add(match[1]);
  }
  for (const name of allSkillNames) {
    if (new RegExp(`(^|[^A-Za-z0-9_-])${escapeRegExp(name)}([^A-Za-z0-9_-]|$)`, "i").test(message)) {
      names.add(name);
    }
  }
  return [...names];
}

function requestsAllSkills(message: string, requested: readonly string[]): boolean {
  if (requested.some((skill) => skill === "*" || skill.toLowerCase() === "all")) {
    return true;
  }
  return /全量\s*skills?|全部\s*skills?|所有\s*skills?|17\s*个\s*skills?|\ball\s+skills?\b/i.test(message);
}

function isKnownSkillName(name: string): name is SkillName {
  return allSkillNameSet.has(name);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
