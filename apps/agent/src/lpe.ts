import type { SanitizedResult } from "./context.js";

export type LpeGraphFinding = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium";
  description: string;
  evidence: string[];
  templates: string[];
  nextSteps: string[];
  expParams?: Record<string, string>;
  confidence: "signal" | "probable";
};

type LpeCard = {
  id: string;
  title: string;
  templateId?: string;
  cves: string[];
  detectionHints: string[];
  prerequisites: string[];
};

type LpeExploitMatch = {
  matched: boolean;
  confidence: "none" | "signal" | "probable";
  reason: string;
  evidenceFactIds: string[];
  missingPrerequisites: string[];
};

type KernelVersion = {
  major: number;
  minor: number;
  patch: number;
  release: string;
};

const lpeCardSeverity: Record<string, "critical" | "high" | "medium"> = {
  "cve-2021-4034-pwnkit": "high",
  "cve-2021-3156-sudo-baron-samedit": "high",
  "cve-2025-32463-sudo-chroot": "high",
  "cve-2017-5618-screen-setuid": "medium",
  "cve-2026-41651-packagekit-pack2theroot": "high",
  "cve-2022-0847-dirty-pipe": "high",
  "cve-2016-5195-dirty-cow": "medium",
  "cve-2026-31431-copy-fail": "critical",
  "cve-2026-43284-43500-dirty-frag": "critical",
  "cve-2023-0386-overlayfs": "high",
  "cve-2021-3493-ubuntu-overlayfs": "medium",
  "cve-2022-0185-fs-context": "high",
  "cve-2024-1086-nftables": "high",
  "cve-2017-16995-ebpf": "high",
  "cve-2021-3490-ebpf-alu32": "high",
};

function cardInherentSeverity(card: LpeCard): "critical" | "high" | "medium" {
  return lpeCardSeverity[card.id] ?? "medium";
}

// Adjust severity down one level for signal-confidence findings (we're less sure it's present)
function severityAdjustedForConfidence(
  inherent: "critical" | "high" | "medium",
  confidence: "probable" | "signal",
): "critical" | "high" | "medium" {
  if (confidence === "probable") return inherent;
  if (inherent === "critical") return "high";
  if (inherent === "high") return "medium";
  return "medium";
}

const lpeCards: LpeCard[] = [
  {
    id: "cve-2021-4034-pwnkit",
    title: "PwnKit pkexec",
    templateId: "cve-2021-4034-pwnkit",
    cves: ["CVE-2021-4034"],
    detectionHints: ["CVE-2021-4034", "PwnKit", "pkexec", "policykit", "polkit"],
    prerequisites: [
      "确认 /usr/bin/pkexec 存在且具备 setuid 权限。",
      "确认 polkit/policykit 包版本与发行版 backport 状态。",
    ],
  },
  {
    id: "cve-2021-3156-sudo-baron-samedit",
    title: "sudo Baron Samedit",
    cves: ["CVE-2021-3156"],
    detectionHints: ["CVE-2021-3156", "Baron Samedit", "sudo"],
    prerequisites: ["确认 sudo 版本和发行版修复包状态。"],
  },
  {
    id: "cve-2025-32463-sudo-chroot",
    title: "sudo chroot NSS loading",
    cves: ["CVE-2025-32463"],
    detectionHints: ["CVE-2025-32463", "sudo chroot", "sudo -R"],
    prerequisites: ["确认 sudo 1.9.14-1.9.17 范围以及发行版补丁状态。"],
  },
  {
    id: "cve-2017-5618-screen-setuid",
    title: "GNU screen 4.5.0 setuid",
    cves: ["CVE-2017-5618"],
    detectionHints: ["CVE-2017-5618", "screen 4.5.0", "setuid screen"],
    prerequisites: ["确认 screen 版本精确为 4.5.0 且二进制具备 setuid-root。"],
  },
  {
    id: "cve-2026-41651-packagekit-pack2theroot",
    title: "PackageKit Pack2TheRoot",
    cves: ["CVE-2026-41651"],
    detectionHints: ["CVE-2026-41651", "PackageKit", "Pack2TheRoot", "packagekitd"],
    prerequisites: ["确认 PackageKit 版本、D-Bus 可达性和发行版 backport 状态。"],
  },
  {
    id: "cve-2022-0847-dirty-pipe",
    title: "Dirty Pipe",
    cves: ["CVE-2022-0847"],
    detectionHints: ["CVE-2022-0847", "Dirty Pipe"],
    prerequisites: ["确认内核是否包含发行版修复补丁。"],
  },
  {
    id: "cve-2016-5195-dirty-cow",
    title: "Dirty COW",
    cves: ["CVE-2016-5195"],
    detectionHints: ["CVE-2016-5195", "Dirty COW"],
    prerequisites: ["确认目标是隔离的旧内核实验环境。"],
  },
  {
    id: "cve-2026-31431-copy-fail",
    title: "Copy Fail AF_ALG",
    cves: ["CVE-2026-31431"],
    detectionHints: ["CVE-2026-31431", "Copy Fail", "AF_ALG"],
    prerequisites: ["确认 AF_ALG AEAD/authenc 内核配置和目标内核分支。"],
  },
  {
    id: "cve-2026-43284-43500-dirty-frag",
    title: "Dirty Frag xfrm/RxRPC",
    cves: ["CVE-2026-43284", "CVE-2026-43500"],
    detectionHints: ["CVE-2026-43284", "CVE-2026-43500", "Dirty Frag", "xfrm", "RxRPC"],
    prerequisites: ["确认 xfrm/ESP 或 RxRPC 可达性，以及 user namespace/CAP_SYS_ADMIN 前置条件。"],
  },
  {
    id: "cve-2023-0386-overlayfs",
    title: "OverlayFS FUSE copy-up",
    cves: ["CVE-2023-0386"],
    detectionHints: ["CVE-2023-0386", "OverlayFS", "FUSE"],
    prerequisites: ["确认 OverlayFS、FUSE 和 unprivileged user namespace 可达。"],
  },
  {
    id: "cve-2021-3493-ubuntu-overlayfs",
    title: "Ubuntu OverlayFS file capabilities",
    cves: ["CVE-2021-3493"],
    detectionHints: ["CVE-2021-3493", "Ubuntu OverlayFS"],
    prerequisites: ["确认 Ubuntu 特定内核补丁状态，不能只看 upstream 版本号。"],
  },
  {
    id: "cve-2022-0185-fs-context",
    title: "fs_context heap overflow",
    cves: ["CVE-2022-0185"],
    detectionHints: ["CVE-2022-0185", "fs_context"],
    prerequisites: ["确认 user namespace 或 CAP_SYS_ADMIN 前置条件。"],
  },
  {
    id: "cve-2024-1086-nftables",
    title: "nf_tables netfilter UAF",
    cves: ["CVE-2024-1086"],
    detectionHints: ["CVE-2024-1086", "nf_tables", "netfilter"],
    prerequisites: ["确认 nf_tables、内核分支和 unprivileged user namespace 状态。"],
  },
  {
    id: "cve-2017-16995-ebpf",
    title: "eBPF verifier 2017",
    cves: ["CVE-2017-16995"],
    detectionHints: ["CVE-2017-16995", "eBPF verifier", "CONFIG_BPF_SYSCALL"],
    prerequisites: ["确认 CONFIG_BPF_SYSCALL 与 kernel.unprivileged_bpf_disabled=0。"],
  },
  {
    id: "cve-2021-3490-ebpf-alu32",
    title: "eBPF ALU32 verifier",
    cves: ["CVE-2021-3490"],
    detectionHints: ["CVE-2021-3490", "eBPF ALU32", "CONFIG_BPF_SYSCALL"],
    prerequisites: ["确认 CONFIG_BPF_SYSCALL 与 kernel.unprivileged_bpf_disabled=0。"],
  },
];

export function buildLpeCatalogFindings(result: SanitizedResult): LpeGraphFinding[] {
  const out: LpeGraphFinding[] = [];
  for (const card of lpeCards) {
    if (hasDocumentLpeFinding(result, card)) continue;
    const match = matchLpeExploit(card, result);
    if (!match.matched || match.confidence === "none") continue;
    const templateId = card.templateId ?? "external-cve-poc";
    const inherentSeverity = cardInherentSeverity(card);
    out.push({
      id: `lpe-catalog:${card.id}`,
      title: card.title,
      severity: severityAdjustedForConfidence(inherentSeverity, match.confidence),
      description: `${match.reason}（固有严重度: ${inherentSeverity}）`,
      evidence: match.evidenceFactIds,
      templates: [templateId],
      expParams: templateId === "external-cve-poc" ? { pocId: card.id, binaryName: card.id } : undefined,
      confidence: match.confidence,
      nextSteps: [
        "进入 EXP Forge 生成对应验证包。",
        ...card.prerequisites.slice(0, 3),
        ...match.missingPrerequisites.map((item) => `待补充：${item}`),
      ],
    });
  }
  return out;
}

export function lpeTemplatesForText(value: string): string[] {
  const text = value.toLowerCase();
  const out = new Set<string>();
  for (const card of lpeCards) {
    if (cardMatchesText(card, text)) out.add(card.templateId ?? "external-cve-poc");
  }
  if (!out.size && text.includes("cve-")) out.add("external-cve-poc");
  return Array.from(out);
}

export function lpeExpParamsForText(value: string, templates: string[]): Record<string, string> | undefined {
  if (!templates.includes("external-cve-poc")) return undefined;
  const text = value.toLowerCase();
  const card = lpeCards.find((item) => cardMatchesText(item, text));
  if (card) return { pocId: card.id, binaryName: card.id };
  const cve = text.match(/cve-\d{4}-\d{4,7}/)?.[0];
  return cve ? { pocId: cve, binaryName: cve } : undefined;
}

function matchLpeExploit(card: LpeCard, result: SanitizedResult): LpeExploitMatch {
  const facts = factMap(result);
  if (card.id === "cve-2021-4034-pwnkit") return matchPwnKit(facts);
  const factMatch = matchLpeExploitFacts(card, facts);
  return factMatch ?? noExploitMatch("当前扫描结果未命中该漏洞指纹");
}

function hasDocumentLpeFinding(result: SanitizedResult, card: LpeCard): boolean {
  return result.findings.some((finding) => {
    if (String(finding.category ?? "") !== "lpe") return false;
    const text = `${finding.title ?? ""} ${finding.description ?? ""}`.toLowerCase();
    return cardMatchesText(card, text);
  });
}

function cardMatchesText(card: LpeCard, text: string): boolean {
  return card.cves.some((cve) => text.includes(cve.toLowerCase())) ||
    card.detectionHints.some((hint) => text.includes(hint.toLowerCase())) ||
    text.includes(card.title.toLowerCase());
}

function matchPwnKit(facts: Map<string, unknown>): LpeExploitMatch {
  const evidence = new Set<string>();
  const pkexec = suidTool(facts, "pkexec");
  if (pkexec?.setuid) evidence.add("lpe.suid_tools");
  const pkexecUsable = suidToolUsable(facts, "pkexec") && suidTransitionsLikely(facts);
  const packages = ["policykit-1", "polkit", "polkitd"]
    .map((name) => ({ name, version: packageVersion(facts, name) }))
    .filter((item) => item.version);
  const vulnerablePackages = packages.filter((item) => pwnKitPackagePotentiallyVulnerable(facts, item.version).vulnerable);
  if (packages.length > 0) evidence.add("lpe.packages");
  if (facts.has("lpe.status")) evidence.add("lpe.status");

  if (!lpeFactsEligible(facts)) return noExploitMatch("当前目标为 root 或 LPE 扫描被跳过");

  if (pkexec?.setuid && vulnerablePackages.length > 0) {
    return {
      matched: true,
      confidence: pkexecUsable ? "probable" : "signal",
      reason: pkexecUsable
        ? `发现 setuid pkexec，且 ${vulnerablePackages.map((item) => `${item.name} ${item.version}`).join(", ")} 低于已知修复版本`
        : "发现 setuid pkexec 和易受影响 polkit 包，但当前 mount/no_new_privs 状态可能阻断 SUID 提权",
      evidenceFactIds: Array.from(evidence),
      missingPrerequisites: pkexecUsable ? [] : ["usable SUID transition without nosuid/NoNewPrivs blocking"],
    };
  }

  if (pkexecUsable && packages.length === 0) {
    return {
      matched: true,
      confidence: "signal",
      reason: "发现 setuid pkexec，但扫描结果未包含 polkit/policykit 包版本",
      evidenceFactIds: Array.from(evidence),
      missingPrerequisites: ["polkit/policykit package version evidence"],
    };
  }

  return noExploitMatch("未发现 setuid pkexec 与易受影响 polkit 包版本组合");
}

function matchLpeExploitFacts(card: LpeCard, facts: Map<string, unknown>): LpeExploitMatch | null {
  if (!lpeFactsEligible(facts)) return null;
  const kernel = kernelVersionFromFacts(facts);
  const userns = usernsState(facts);
  const hasCAPSysAdmin = capEffectiveHas(facts, 21);
  const bpfEnabled = kernelConfigEnabled(facts, "CONFIG_BPF_SYSCALL").enabled;
  const unprivBPFEnabled = sysctlEquals(facts, "kernel.unprivileged_bpf_disabled", "0");

  switch (card.id) {
    case "cve-2021-3156-sudo-baron-samedit": {
      const version = packageVersion(facts, "sudo");
      const status = sudo3156PackagePotentiallyVulnerable(facts, version);
      return status.vulnerable ? factMatch("signal", `sudo package version ${version} ${status.reason}`, ["lpe.packages"]) : null;
    }
    case "cve-2025-32463-sudo-chroot": {
      const version = packageVersion(facts, "sudo");
      if (version && compareNumericVersion(version, "1.9.14") >= 0 && compareNumericVersion(version, "1.9.17") <= 0) {
        return factMatch("signal", `sudo package version ${version} falls in the 1.9.14-1.9.17 heuristic range`, ["lpe.packages"]);
      }
      return null;
    }
    case "cve-2017-5618-screen-setuid": {
      const version = packageVersion(facts, "screen");
      const screen = suidTool(facts, "screen");
      if (version && compareNumericVersion(version, "4.5.0") === 0 && screen?.setuid) {
        const usable = suidToolUsable(facts, "screen") && suidTransitionsLikely(facts);
        return factMatch(usable ? "probable" : "signal", usable ? "screen 4.5.0 is installed and the screen binary setuid appears usable" : "screen 4.5.0 is installed and setuid, but current mount/no_new_privs state may block SUID transitions", ["lpe.packages", "lpe.suid_tools"]);
      }
      return null;
    }
    case "cve-2026-41651-packagekit-pack2theroot": {
      const version = packageVersion(facts, "packagekit");
      const status = packageKitPotentiallyVulnerable(facts, version);
      if (status.vulnerable) {
        return factMatch("signal", `PackageKit version ${version} ${status.reason}; D-Bus activation/service reachability was not confirmed`, ["lpe.packages"]);
      }
      return null;
    }
    case "cve-2022-0847-dirty-pipe":
      return kernel && kernelInDirtyPipeRange(kernel)
        ? factMatch("signal", `kernel release ${kernel.release} falls in a Dirty Pipe pre-fix branch`, ["lpe.kernel"])
        : null;
    case "cve-2016-5195-dirty-cow":
      return kernel && compareKernelVersion(kernel, kv(4, 8, 3)) < 0
        ? factMatch("signal", `kernel release ${kernel.release} is older than the common CVE-2016-5195 fixed range`, ["lpe.kernel"])
        : null;
    case "cve-2026-31431-copy-fail":
      return kernel && kernelInCopyFailRange(kernel) && kernelConfigAllEnabled(facts, "CONFIG_CRYPTO_USER_API_AEAD", "CONFIG_CRYPTO_AUTHENC")
        ? factMatch("probable", "kernel range and AF_ALG AEAD/authenc kernel config match Copy Fail prerequisites", ["lpe.kernel", "lpe.kernel_config"])
        : null;
    case "cve-2026-43284-43500-dirty-frag":
      if (kernel && (userns.enabled || hasCAPSysAdmin)) {
        const esp = kernelInDirtyFragESPRange(kernel) && dirtyFragESPReachable(facts);
        const rxrpc = kernelInDirtyFragRxRPCRange(kernel) && dirtyFragRxRPCReachable(facts);
        if (esp || rxrpc) {
          return factMatch("probable", "kernel range, network crypto reachability, and namespace/capability prerequisites match Dirty Frag signals", [
            "lpe.kernel",
            "lpe.kernel_config",
            "lpe.modules",
            "lpe.sysctls",
            "lpe.process_security",
          ]);
        }
      }
      return null;
    case "cve-2023-0386-overlayfs": {
      const overlay = modulePresent(facts, "overlay") || filesystemBool(facts, "hasOverlay");
      const fuse = modulePresent(facts, "fuse") || filesystemBool(facts, "hasFuse");
      if (kernel && kernelBetween(kernel, kv(5, 11, 0), kv(6, 2, 999)) && overlay && userns.enabled) {
        const evidence = ["lpe.kernel", "lpe.modules", "lpe.filesystems", "lpe.sysctls"];
        return fuse
          ? factMatch("probable", "kernel range plus OverlayFS/FUSE/userns signals match public exploit prerequisites", evidence)
          : factMatch("signal", "OverlayFS and user namespaces are present; FUSE signal was not observed", evidence, ["FUSE reachability"]);
      }
      return null;
    }
    case "cve-2021-3493-ubuntu-overlayfs": {
      const overlay = modulePresent(facts, "overlay") || filesystemBool(facts, "hasOverlay");
      return kernel && kernelLooksLikeUbuntu(facts) && kernelBetween(kernel, kv(3, 13, 0), kv(5, 13, 999)) && overlay
        ? factMatch("signal", "Ubuntu kernel release and OverlayFS signal match public suggester heuristics", ["lpe.kernel", "lpe.modules", "lpe.filesystems"])
        : null;
    }
    case "cve-2022-0185-fs-context":
      return kernel && kernelBetween(kernel, kv(5, 4, 0), kv(5, 16, 2)) && (userns.enabled || hasCAPSysAdmin)
        ? factMatch("signal", "kernel range and namespace/capability prerequisites match common public exploit requirements", [
          "lpe.kernel",
          "lpe.sysctls",
          "lpe.process_security",
        ])
        : null;
    case "cve-2024-1086-nftables":
      if (kernel && kernelInNfTables1086ExploitRange(kernel) && modulePresent(facts, "nf_tables")) {
        if (userns.enabled) {
          const caveat = nfTablesInitOnAllocCaveat(kernel, facts);
          const confidence = caveat || kernelReleaseLooksVendorPatched(kernel.release) ? "signal" : "probable";
          const reason = caveat
            ? "kernel range, nf_tables, and userns match, but CONFIG_INIT_ON_ALLOC_DEFAULT_ON is enabled on a 6.4+ kernel"
            : "kernel range, nf_tables presence, and unprivileged user namespaces match public exploit prerequisites";
          return factMatch(confidence, reason, ["lpe.kernel", "lpe.modules", "lpe.sysctls"]);
        }
        if (!userns.known) return factMatch("signal", "nf_tables and kernel range are present, but user namespace state is unknown", ["lpe.kernel", "lpe.modules"], ["unprivileged user namespace state"]);
      }
      return null;
    case "cve-2017-16995-ebpf":
      return kernel && bpfEnabled && unprivBPFEnabled && kernelBetween(kernel, kv(4, 4, 0), kv(4, 14, 8))
        ? factMatch("probable", "kernel range, CONFIG_BPF_SYSCALL, and enabled unprivileged BPF match public exploit prerequisites", ["lpe.kernel", "lpe.kernel_config", "lpe.sysctls"])
        : null;
    case "cve-2021-3490-ebpf-alu32":
      return kernel && bpfEnabled && unprivBPFEnabled && kernelBetween(kernel, kv(5, 7, 0), kv(5, 11, 999))
        ? factMatch("probable", "kernel range, CONFIG_BPF_SYSCALL, and enabled unprivileged BPF match public exploit prerequisites", ["lpe.kernel", "lpe.kernel_config", "lpe.sysctls"])
        : null;
    default:
      return null;
  }
}

function factMatch(confidence: "signal" | "probable", reason: string, evidenceFactIds: string[], missingPrerequisites: string[] = []): LpeExploitMatch {
  return { matched: true, confidence, reason, evidenceFactIds, missingPrerequisites };
}

function noExploitMatch(reason: string): LpeExploitMatch {
  return { matched: false, confidence: "none", reason, evidenceFactIds: [], missingPrerequisites: [] };
}

function factMap(result: SanitizedResult): Map<string, unknown> {
  return new Map(result.facts.map((fact) => [fact.id, fact.value]));
}

function packageVersion(facts: Map<string, unknown>, name: string): string {
  const packages = arrayOfRecords(asRecord(facts.get("lpe.packages")).packages);
  const item = packages.find((pkg) => stringValue(pkg.name) === name);
  return stringValue(item?.version) ?? "";
}

function suidTool(facts: Map<string, unknown>, name: string): { path?: string; setuid?: boolean; nosuid?: boolean; isDir?: boolean } | null {
  const tool = arrayOfRecords(facts.get("lpe.suid_tools")).find((item) => stringValue(item.name) === name);
  return tool ? { path: stringValue(tool.path), setuid: tool.setuid === true, nosuid: tool.nosuid === true, isDir: tool.isDir === true } : null;
}

function suidToolUsable(facts: Map<string, unknown>, name: string): boolean {
  const tool = suidTool(facts, name);
  return Boolean(tool?.setuid) && tool?.isDir !== true && tool?.nosuid !== true;
}

function suidTransitionsLikely(facts: Map<string, unknown>): boolean {
  return String(asRecord(facts.get("lpe.process_security")).noNewPrivs ?? "").trim() !== "1";
}

function lpeFactsEligible(facts: Map<string, unknown>): boolean {
  const status = asRecord(facts.get("lpe.status"));
  if (status.skipped === true) return false;
  const identity = asRecord(facts.get("identity.current_user"));
  const euid = numberValue(identity.euid) ?? numberValue(status.euid) ?? 1000;
  return euid !== 0;
}

function osReleaseField(facts: Map<string, unknown>, key: string): string {
  return stringValue(asRecord(asRecord(facts.get("lpe.kernel")).osRelease)[key]) ?? "";
}

function packageKitPotentiallyVulnerable(facts: Map<string, unknown>, version: string): { vulnerable: boolean; reason: string } {
  if (!version) return { vulnerable: false, reason: "" };
  if (osReleaseField(facts, "ID").toLowerCase() === "ubuntu") {
    const fixed = ubuntuPackageKitFixedVersion(osReleaseField(facts, "VERSION_ID"));
    if (fixed) {
      return compareNumericVersion(version, fixed) < 0
        ? { vulnerable: true, reason: `is below Ubuntu fixed package version ${fixed}` }
        : { vulnerable: false, reason: "" };
    }
  }
  return compareNumericVersion(version, "1.0.2") >= 0 && compareNumericVersion(version, "1.3.5") < 0
    ? { vulnerable: true, reason: "is in the upstream affected range >=1.0.2 <1.3.5; verify distro backports" }
    : { vulnerable: false, reason: "" };
}

function ubuntuPackageKitFixedVersion(versionId: string): string {
  const versions: Record<string, string> = {
    "16.04": "0.8.17-4ubuntu6~gcc5.4ubuntu1.5+esm1",
    "18.04": "1.1.9-1ubuntu2.18.04.6+esm1",
    "20.04": "1.1.13-2ubuntu1.1+esm1",
    "22.04": "1.2.5-2ubuntu3.1",
    "24.04": "1.2.8-2ubuntu1.5",
    "25.10": "1.3.1-1ubuntu1.1",
    "26.04": "1.3.4-3ubuntu1",
  };
  return versions[versionId.replaceAll("\"", "")] ?? "";
}

function pwnKitPackagePotentiallyVulnerable(facts: Map<string, unknown>, version: string): { vulnerable: boolean; reason: string } {
  if (!version) return { vulnerable: false, reason: "" };
  if (osReleaseField(facts, "ID").toLowerCase() === "ubuntu") {
    const fixed = ubuntuPwnKitFixedVersion(osReleaseField(facts, "VERSION_ID"));
    if (fixed) {
      return compareNumericVersion(version, fixed) < 0
        ? { vulnerable: true, reason: `is below Ubuntu fixed package version ${fixed}` }
        : { vulnerable: false, reason: "" };
    }
  }
  return compareNumericVersion(version, "0.105-31") <= 0
    ? { vulnerable: true, reason: "falls in the generic upstream pre-0.105-31 heuristic range" }
    : { vulnerable: false, reason: "" };
}

function ubuntuPwnKitFixedVersion(versionId: string): string {
  const versions: Record<string, string> = {
    "14.04": "0.105-4ubuntu3.14.04.6",
    "16.04": "0.105-14.1ubuntu0.5",
    "18.04": "0.105-20ubuntu0.18.04.6",
    "20.04": "0.105-26ubuntu1.2",
    "21.10": "0.105-31ubuntu0.1",
    "22.04": "0.105-31ubuntu1",
  };
  return versions[versionId.replaceAll("\"", "")] ?? "";
}

function sudo3156PackagePotentiallyVulnerable(facts: Map<string, unknown>, version: string): { vulnerable: boolean; reason: string } {
  if (!version) return { vulnerable: false, reason: "" };
  if (osReleaseField(facts, "ID").toLowerCase() === "ubuntu") {
    const fixed = ubuntuSudo3156FixedVersion(osReleaseField(facts, "VERSION_ID"));
    if (fixed) {
      return compareNumericVersion(version, fixed) < 0
        ? { vulnerable: true, reason: `is below Ubuntu fixed package version ${fixed}; verify vendor backports` }
        : { vulnerable: false, reason: "" };
    }
  }
  return compareNumericVersion(version, "1.9.5p2") < 0
    ? { vulnerable: true, reason: "is below upstream 1.9.5p2; verify vendor backports" }
    : { vulnerable: false, reason: "" };
}

function ubuntuSudo3156FixedVersion(versionId: string): string {
  const versions: Record<string, string> = {
    "14.04": "1.8.9p5-1ubuntu1.5",
    "16.04": "1.8.16-0ubuntu1.10",
    "18.04": "1.8.21p2-3ubuntu1.4",
    "20.04": "1.8.31-1ubuntu1.2",
    "20.10": "1.9.1-1ubuntu1.1",
  };
  return versions[versionId.replaceAll("\"", "")] ?? "";
}

function kernelVersionFromFacts(facts: Map<string, unknown>): KernelVersion | null {
  const release = stringValue(asRecord(facts.get("lpe.kernel")).release) ?? "";
  if (!release) return null;
  const head = release.split("-", 1)[0];
  const parts = head.split(".");
  if (parts.length < 2) return null;
  const major = Number.parseInt(parts[0] ?? "", 10);
  const minor = Number.parseInt(parts[1] ?? "", 10);
  const patch = Number.parseInt(parts[2] ?? "0", 10);
  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return null;
  return { major, minor, patch, release };
}

function kv(major: number, minor: number, patch: number): KernelVersion {
  return { major, minor, patch, release: `${major}.${minor}.${patch}` };
}

function compareKernelVersion(a: KernelVersion, b: KernelVersion): number {
  return compareNumberTuple([a.major, a.minor, a.patch], [b.major, b.minor, b.patch]);
}

function kernelBetween(value: KernelVersion, min: KernelVersion, max: KernelVersion): boolean {
  return compareKernelVersion(value, min) >= 0 && compareKernelVersion(value, max) <= 0;
}

function kernelInRanges(value: KernelVersion, ranges: Array<[KernelVersion, KernelVersion]>): boolean {
  return ranges.some(([min, max]) => kernelBetween(value, min, max));
}

function kernelInDirtyPipeRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(5, 8, 0), kv(5, 9, 999)],
    [kv(5, 10, 0), kv(5, 10, 101)],
    [kv(5, 11, 0), kv(5, 14, 999)],
    [kv(5, 15, 0), kv(5, 15, 24)],
    [kv(5, 16, 0), kv(5, 16, 10)],
  ]);
}

function kernelInNfTables1086ExploitRange(value: KernelVersion): boolean {
  if (!kernelBetween(value, kv(5, 14, 0), kv(6, 6, 999))) return false;
  if (value.major === 5 && value.minor === 15 && value.patch >= 149) return false;
  if (value.major === 6 && value.minor === 1 && value.patch >= 76) return false;
  if (value.major === 6 && value.minor === 6 && value.patch >= 15) return false;
  return true;
}

function kernelInCopyFailRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(4, 14, 0), kv(5, 10, 253)],
    [kv(5, 11, 0), kv(5, 15, 203)],
    [kv(5, 16, 0), kv(6, 1, 169)],
    [kv(6, 2, 0), kv(6, 6, 136)],
    [kv(6, 7, 0), kv(6, 12, 84)],
    [kv(6, 13, 0), kv(6, 18, 21)],
    [kv(6, 19, 0), kv(6, 19, 11)],
  ]);
}

function kernelInDirtyFragESPRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(4, 11, 0), kv(5, 10, 254)],
    [kv(5, 12, 0), kv(5, 15, 204)],
    [kv(5, 16, 0), kv(6, 1, 170)],
    [kv(6, 2, 0), kv(6, 6, 137)],
    [kv(6, 7, 0), kv(6, 12, 86)],
    [kv(6, 13, 0), kv(6, 18, 27)],
    [kv(7, 0, 0), kv(7, 0, 4)],
  ]);
}

function kernelInDirtyFragRxRPCRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(5, 4, 0), kv(6, 18, 28)],
    [kv(6, 19, 0), kv(7, 0, 5)],
  ]);
}

function compareNumericVersion(a: string, b: string): number {
  return compareNumberTuple(numericVersionParts(a), numericVersionParts(b));
}

function numericVersionParts(value: string): number[] {
  const withoutEpoch = value.includes(":") ? value.split(":").slice(1).join(":") : value;
  return Array.from(withoutEpoch.matchAll(/\d+/g), (match) => Number.parseInt(match[0], 10));
}

function compareNumberTuple(a: number[], b: number[]): number {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) return av > bv ? 1 : -1;
  }
  return 0;
}

function modulePresent(facts: Map<string, unknown>, name: string): boolean {
  const modules = asRecord(facts.get("lpe.modules"));
  return arrayIncludesString(modules.present, name) || arrayIncludesString(modules.loadedNames, name);
}

function kernelConfigValue(facts: Map<string, unknown>, key: string): string {
  return stringValue(asRecord(asRecord(facts.get("lpe.kernel_config")).values)[key]) ?? "";
}

function kernelConfigEnabled(facts: Map<string, unknown>, key: string): { known: boolean; enabled: boolean } {
  const value = kernelConfigValue(facts, key);
  return { known: Boolean(value), enabled: value === "y" || value === "m" };
}

function kernelConfigAllEnabled(facts: Map<string, unknown>, ...keys: string[]): boolean {
  return keys.every((key) => kernelConfigEnabled(facts, key).enabled);
}

function sysctlEquals(facts: Map<string, unknown>, key: string, expected: string): boolean {
  return String(asRecord(facts.get("lpe.sysctls"))[key] ?? "").trim() === expected;
}

function usernsState(facts: Map<string, unknown>): { known: boolean; enabled: boolean } {
  const sysctls = asRecord(facts.get("lpe.sysctls"));
  const clone = sysctls["kernel.unprivileged_userns_clone"];
  if (clone !== undefined) return { known: true, enabled: String(clone).trim() === "1" };
  const max = sysctls["user.max_user_namespaces"];
  if (max !== undefined) {
    const value = Number.parseInt(String(max).trim(), 10);
    if (Number.isFinite(value)) return { known: true, enabled: value > 0 };
  }
  return { known: false, enabled: false };
}

function filesystemBool(facts: Map<string, unknown>, key: string): boolean {
  return asRecord(facts.get("lpe.filesystems"))[key] === true;
}

function capEffectiveHas(facts: Map<string, unknown>, bit: number): boolean {
  const effective = stringValue(asRecord(asRecord(facts.get("lpe.process_security")).capabilities).effective) ?? "";
  if (!effective) return false;
  const value = Number.parseInt(effective, 16);
  return Number.isFinite(value) && (value & (2 ** bit)) !== 0;
}

function dirtyFragESPReachable(facts: Map<string, unknown>): boolean {
  if (modulePresent(facts, "esp4") || modulePresent(facts, "esp6")) return true;
  const xfrm = kernelConfigEnabled(facts, "CONFIG_XFRM");
  const esp4 = kernelConfigEnabled(facts, "CONFIG_INET_ESP");
  const esp6 = kernelConfigEnabled(facts, "CONFIG_INET6_ESP");
  return xfrm.known && xfrm.enabled && ((esp4.known && esp4.enabled) || (esp6.known && esp6.enabled));
}

function dirtyFragRxRPCReachable(facts: Map<string, unknown>): boolean {
  return modulePresent(facts, "rxrpc") || kernelConfigEnabled(facts, "CONFIG_RXRPC").enabled;
}

function nfTablesInitOnAllocCaveat(kernel: KernelVersion, facts: Map<string, unknown>): boolean {
  return compareKernelVersion(kernel, kv(6, 4, 0)) >= 0 && kernelConfigEnabled(facts, "CONFIG_INIT_ON_ALLOC_DEFAULT_ON").enabled;
}

function kernelReleaseLooksVendorPatched(release: string): boolean {
  const suffix = release.split("-").slice(1).join("-").toLowerCase();
  if (!suffix) return false;
  return ["generic", "amd64", "ubuntu", "deb", "el", "uek", "amzn", "aws", "azure", "gcp", "cloud", "rt", "raspi"]
    .some((marker) => suffix.includes(marker));
}

function kernelLooksLikeUbuntu(facts: Map<string, unknown>): boolean {
  const kernel = asRecord(facts.get("lpe.kernel"));
  const text = `${kernel.release ?? ""} ${kernel.version ?? ""}`.toLowerCase();
  return text.includes("ubuntu") || osReleaseField(facts, "ID").toLowerCase() === "ubuntu";
}

function arrayIncludesString(value: unknown, target: string): boolean {
  return Array.isArray(value) && value.some((item) => String(item) === target);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function arrayOfRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}
