import { createInterface } from "node:readline";
import { loadConfig, publicConfig } from "./config.js";
import { runKubeTrailAgent } from "./agent.js";
import { loadAttackGraph, materializeGraphRef } from "./graph.js";
import { listExpTemplates, renderExpBundle } from "./exp/render.js";
import { renderGraphMarkdown } from "./report.js";

type Request = {
  id: string;
  method: string;
  params?: Record<string, unknown>;
};

type Response = {
  id: string;
  type: "result" | "stream" | "error" | "end";
  data?: unknown;
  error?: string;
};

const activeChats = new Map<string, AbortController>();

function send(msg: Response): void {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function handleRequest(req: Request): Promise<void> {
  try {
    switch (req.method) {
      case "config": {
        send({ id: req.id, type: "result", data: publicConfig(loadConfig()) });
        break;
      }
      case "graph": {
        const graph = await loadAttackGraph(req.params?.inputPath as string);
        send({ id: req.id, type: "result", data: graph });
        break;
      }
      case "materialize": {
        const value = await materializeGraphRef(
          req.params?.inputPath as string,
          req.params?.ref as string,
        );
        send({ id: req.id, type: "result", data: { ref: req.params?.ref, value } });
        break;
      }
      case "chat": {
        const abortController = new AbortController();
        activeChats.set(req.id, abortController);
        try {
          const result = await runKubeTrailAgent({
            message: req.params?.message as string,
            inputPath: req.params?.inputPath as string,
            resumeSession: req.params?.sessionId as string,
            forkSession: req.params?.forkSession === true,
            skills: Array.isArray(req.params?.skills) ? req.params.skills.map(String) : undefined,
            config: { language: normalizePipeLanguage(req.params?.language) },
            abortController,
            onEvent: (event) => {
              if (event.type !== "result") {
                send({ id: req.id, type: "stream", data: event });
              }
            },
          });
          send({ id: req.id, type: "result", data: { sessionId: result.sessionId, text: result.text } });
        } finally {
          activeChats.delete(req.id);
        }
        break;
      }
      case "cancel": {
        const targetId = String(req.params?.id ?? req.params?.targetId ?? "");
        const controller = activeChats.get(targetId);
        if (controller) {
          controller.abort();
        }
        send({ id: req.id, type: "result", data: { cancelled: Boolean(controller) } });
        break;
      }
      case "list-exp-templates": {
        const templates = listExpTemplates();
        send({ id: req.id, type: "result", data: { templates } });
        break;
      }
      case "generate-exp": {
        const result = await renderExpBundle({
          templateId: req.params?.templateId as string,
          outDir: req.params?.outDir as string | undefined,
          params: req.params?.params as Record<string, unknown> | undefined,
          findingIds: req.params?.findingIds as string[] | undefined,
          factIds: req.params?.factIds as string[] | undefined,
          sensitiveRefs: req.params?.sensitiveRefs as string[] | undefined,
        });
        send({ id: req.id, type: "result", data: result });
        break;
      }
      case "export-report": {
        const graph = await loadAttackGraph(req.params?.inputPath as string);
        const format = (req.params?.format as string) ?? "json";
        if (format === "markdown") {
          send({ id: req.id, type: "result", data: { format: "markdown", content: renderGraphMarkdown(graph) } });
        } else {
          send({ id: req.id, type: "result", data: { format: "json", content: graph } });
        }
        break;
      }
      default:
        send({ id: req.id, type: "error", error: `unknown method: ${req.method}` });
    }
  } catch (err) {
    send({ id: req.id, type: "error", error: err instanceof Error ? err.message : String(err) });
  }
  send({ id: req.id, type: "end" });
}

function normalizePipeLanguage(value: unknown): "zh-CN" | "en-US" | undefined {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (normalized === "en" || normalized === "en-us") {
    return "en-US";
  }
  if (normalized === "zh" || normalized === "zh-cn") {
    return "zh-CN";
  }
  return undefined;
}

export async function runPipe(): Promise<void> {
  send({ id: "_ready", type: "result", data: { ready: true } });

  const rl = createInterface({ input: process.stdin, terminal: false });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let req: Request;
    try {
      req = JSON.parse(trimmed) as Request;
    } catch {
      send({ id: "_parse_error", type: "error", error: `invalid JSON: ${trimmed.slice(0, 100)}` });
      send({ id: "_parse_error", type: "end" });
      continue;
    }
    if (!req.id || !req.method) {
      send({ id: req.id ?? "_invalid", type: "error", error: "missing id or method" });
      send({ id: req.id ?? "_invalid", type: "end" });
      continue;
    }
    void handleRequest(req);
  }
}
