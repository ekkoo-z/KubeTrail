import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export type RawFact = {
  id?: string;
  collector?: string;
  category?: string;
  source?: string;
  sensitive?: boolean;
  value?: unknown;
};

export type RawFinding = {
  severity?: string;
  category?: string;
  confidence?: string;
  title?: string;
  description?: string;
  evidence?: unknown;
};

export type SanitizedFact = {
  id: string;
  collector: string;
  category: string;
  source?: string;
  sensitive?: boolean;
  value: unknown;
};

export type SensitiveRef = {
  ref: string;
  factId: string;
  collector: string;
  category: string;
  source?: string;
  kind: string;
  present: boolean;
  bytes?: number;
  sha256?: string;
  materializable: boolean;
  metadata: Record<string, unknown>;
  note: string;
};

export type SanitizedResult = {
  path: string;
  schemaVersion?: string;
  mode?: string;
  target?: unknown;
  run?: unknown;
  collectors: unknown[];
  facts: SanitizedFact[];
  findings: RawFinding[];
  sensitiveRefs: SensitiveRef[];
  errors: unknown[];
  sensitiveMaterial: Map<string, unknown>;
};

export type ResultSummary = {
  path: string;
  schemaVersion?: string;
  mode?: string;
  factCount: number;
  collectorCount: number;
  sensitiveRefCount: number;
  errorCount: number;
  target?: unknown;
};

export class KubeTrailContextStore {
  private result?: SanitizedResult;

  constructor(private readonly defaultPath: string) {}

  async load(inputPath?: string): Promise<SanitizedResult> {
    const target = inputPath?.trim() || this.defaultPath.trim();
    if (!target) {
      throw new Error("No KubeTrail result path is configured. Import a scan result or pass an explicit result path.");
    }
    const path = resolve(target);
    const data = await readFile(path, "utf8");
    const raw = JSON.parse(data) as Record<string, unknown>;
    this.result = sanitizeDocument(raw, path);
    return this.result;
  }

  current(): SanitizedResult {
    if (!this.result) {
      throw new Error("No KubeTrail result is loaded. Call kubetrail_load_result first.");
    }
    return this.result;
  }

  summary(): ResultSummary {
    return summarize(this.current());
  }
}

export function summarize(result: SanitizedResult): ResultSummary {
  return {
    path: result.path,
    schemaVersion: result.schemaVersion,
    mode: result.mode,
    factCount: result.facts.length,
    collectorCount: result.collectors.length,
    sensitiveRefCount: result.sensitiveRefs.length,
    errorCount: result.errors.length,
    target: result.target,
  };
}

export function listFacts(result: SanitizedResult, filter?: string, limit = 50): SanitizedFact[] {
  const needle = filter?.trim().toLowerCase();
  const facts = needle
    ? result.facts.filter((fact) =>
        [fact.id, fact.collector, fact.category, fact.source ?? "", JSON.stringify(fact.value)]
          .join(" ")
          .toLowerCase()
          .includes(needle),
      )
    : result.facts;
  return facts.slice(0, Math.max(1, Math.min(limit, 500)));
}

export function getFact(result: SanitizedResult, id: string): SanitizedFact | undefined {
  return result.facts.find((fact) => fact.id === id);
}

export function materialize(result: SanitizedResult, ref: string): unknown {
  if (!result.sensitiveMaterial.has(ref)) {
    throw new Error(`Unknown sensitive ref: ${ref}`);
  }
  return result.sensitiveMaterial.get(ref);
}

function sanitizeDocument(raw: Record<string, unknown>, path: string): SanitizedResult {
  const facts = Array.isArray(raw.facts) ? (raw.facts as RawFact[]) : flattenCollectorFacts(raw);
  const sensitiveMaterial = new Map<string, unknown>();
  const sensitiveRefs: SensitiveRef[] = [];
  const sanitizedFacts = facts.map((fact, index) => {
    const normalized: SanitizedFact = {
      id: stringOr(fact.id, `fact-${index}`),
      collector: stringOr(fact.collector, "unknown"),
      category: stringOr(fact.category, "unknown"),
      source: fact.source,
      sensitive: fact.sensitive,
      value: fact.value,
    };
    if (fact.sensitive && !emptySensitiveValue(fact.value)) {
      const ref = buildSensitiveRef(normalized, fact.value, index);
      sensitiveRefs.push(ref);
      sensitiveMaterial.set(ref.ref, fact.value);
      normalized.value = {
        sensitive: true,
        ref: ref.ref,
        kind: ref.kind,
        metadata: ref.metadata,
        materializable: ref.materializable,
        note: "敏感明文未直接暴露给 Agent；该 ref 代表本地客户端持有的授权材料。",
      };
    }
    return normalized;
  });

  return {
    path,
    schemaVersion: stringOrUndefined(raw.schemaVersion),
    mode: stringOrUndefined(raw.mode),
    target: raw.target,
    run: raw.run,
    collectors: Array.isArray(raw.collectors) ? raw.collectors : [],
    facts: sanitizedFacts,
    findings: Array.isArray(raw.findings) ? (raw.findings as RawFinding[]) : [],
    sensitiveRefs,
    errors: Array.isArray(raw.errors) ? raw.errors : [],
    sensitiveMaterial,
  };
}

function flattenCollectorFacts(raw: Record<string, unknown>): RawFact[] {
  const collectors = Array.isArray(raw.collectors) ? raw.collectors : [];
  const facts: RawFact[] = [];
  for (const collector of collectors) {
    if (!collector || typeof collector !== "object") {
      continue;
    }
    const value = collector as Record<string, unknown>;
    if (Array.isArray(value.facts)) {
      for (const fact of value.facts) {
        if (fact && typeof fact === "object") {
          facts.push(fact as RawFact);
        }
      }
    }
  }
  return facts;
}

function buildSensitiveRef(fact: SanitizedFact, value: unknown, index: number): SensitiveRef {
  const encoded = JSON.stringify(value);
  const sha256 = createHash("sha256").update(encoded).digest("hex");
  const metadata = {
    present: true,
    bytes: Buffer.byteLength(encoded),
    sha256,
    shape: shape(value),
  };
  return {
    ref: `sensitive://fact/${slug(fact.id)}/${index}`,
    factId: fact.id,
    collector: fact.collector,
    category: fact.category,
    source: fact.source,
    kind: classifyKind(fact),
    present: true,
    bytes: metadata.bytes,
    sha256,
    materializable: true,
    metadata,
    note: "raw material is available in the local KubeTrail agent process",
  };
}

function classifyKind(fact: SanitizedFact): string {
  const value = `${fact.id} ${fact.collector} ${fact.category} ${fact.source ?? ""}`.toLowerCase();
  if (value.includes("serviceaccount")) return "service_account_material";
  if (value.includes("credential_sweep")) return "credential_file";
  if (value.includes("environment")) return "env_secret";
  if (value.includes("cloud_metadata")) return "cloud_metadata";
  if (value.includes("secret")) return "kubernetes_secret";
  if (value.includes("pod")) return "pod_spec";
  if (value.includes("k8s")) return "kubernetes_object_snapshot";
  return "sensitive_fact";
}

function shape(value: unknown): Record<string, unknown> {
  if (Array.isArray(value)) return { type: "array", items: value.length };
  if (value && typeof value === "object") return { type: "object", keys: Object.keys(value) };
  return { type: typeof value };
}

function emptySensitiveValue(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === "string") return value === "";
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === "string" && value !== "" ? value : fallback;
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function slug(value: string): string {
  const out = value.replace(/[^a-zA-Z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "");
  return out || "unknown";
}
