import { createSdkMcpServer, tool } from "@anthropic-ai/claude-agent-sdk";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { AgentRuntimeConfig } from "../config.js";
import { getFact, KubeTrailContextStore, listFacts, materialize, summarize } from "../context.js";
import { expTemplateIds } from "../exp/catalog.js";

type ToolResult = {
  isError?: boolean;
  content: Array<{ type: "text"; text: string }>;
};

type KubeTrailToolDefinition = {
  name: string;
  description: string;
  inputSchema: Record<string, z.ZodTypeAny>;
  handler: (args: Record<string, unknown>) => Promise<ToolResult> | ToolResult;
  annotations?: { readOnlyHint?: boolean };
};

export function kubeTrailToolNames(): string[] {
  const raw = [
    "kubetrail_load_result",
    "kubetrail_summary",
    "kubetrail_list_facts",
    "kubetrail_get_fact",
    "kubetrail_list_sensitive_refs",
    "kubetrail_materialize_sensitive",
    "kubetrail_list_exp_templates",
    "kubetrail_generate_exp_plan",
  ];
  return raw.flatMap((name) => [name, `mcp__kubetrail__${name}`]);
}

export function createKubeTrailMcpServer(store: KubeTrailContextStore, config: AgentRuntimeConfig) {
  const definitions = createKubeTrailToolDefinitions(store, config);
  return createSdkMcpServer({
    name: "kubetrail",
    version: "0.1.0",
    alwaysLoad: true,
    tools: definitions.map((definition) =>
      tool(
        definition.name,
        definition.description,
        definition.inputSchema,
        async (args) => definition.handler(args as Record<string, unknown>),
        definition.annotations ? { annotations: definition.annotations } : undefined,
      ),
    ),
  });
}

export async function runKubeTrailMcpStdio(config: AgentRuntimeConfig): Promise<void> {
  const store = new KubeTrailContextStore(config.defaultInputPath);
  const server = new McpServer(
    {
      name: "kubetrail",
      version: "0.1.0",
    },
    {
      instructions: [
        "KubeTrail MCP exposes sanitized Kubernetes situational-awareness facts for authorized analysis.",
        "Call kubetrail_load_result only when the user asks to analyze a KubeTrail scan result or provides a result path.",
        "Sensitive values are returned as sensitive:// refs unless explicit materialization is enabled.",
      ].join(" "),
    },
  );

  for (const definition of createKubeTrailToolDefinitions(store, config)) {
    server.registerTool(
      definition.name,
      {
        description: definition.description,
        inputSchema: definition.inputSchema,
        annotations: definition.annotations,
      },
      async (args) => definition.handler(args as Record<string, unknown>),
    );
  }

  await server.connect(new StdioServerTransport());
}

function createKubeTrailToolDefinitions(store: KubeTrailContextStore, config: AgentRuntimeConfig): KubeTrailToolDefinition[] {
  return [
    {
      name: "kubetrail_load_result",
      description: "Load and sanitize a KubeTrail server JSON result file. Use this only for scan-result analysis or when a result path is provided.",
      inputSchema: {
        path: z.string().optional().describe("Path to dbus.json/result.json. If omitted, uses KUBETRAIL_RESULT_PATH only when configured for this turn."),
      },
      handler: async ({ path }) => {
        const result = await store.load(typeof path === "string" ? path : undefined);
        return ok({ summary: summarize(result) });
      },
      annotations: { readOnlyHint: true },
    },
    {
      name: "kubetrail_summary",
      description: "Return the summary of the currently loaded KubeTrail result.",
      inputSchema: {},
      handler: () => ok({ summary: store.summary() }),
      annotations: { readOnlyHint: true },
    },
    {
      name: "kubetrail_list_facts",
      description: "List sanitized facts from the loaded KubeTrail result. Sensitive values are returned as sensitive:// references only.",
      inputSchema: {
        filter: z.string().optional().describe("Optional substring filter across id, collector, category, source, and value."),
        limit: z.number().int().min(1).max(500).optional().describe("Maximum facts to return."),
      },
      handler: ({ filter, limit }) => {
        const result = store.current();
        const facts = listFacts(result, typeof filter === "string" ? filter : undefined, typeof limit === "number" ? limit : 50);
        return ok({ facts, returned: facts.length, total: result.facts.length });
      },
      annotations: { readOnlyHint: true },
    },
    {
      name: "kubetrail_get_fact",
      description: "Get one sanitized fact by fact id.",
      inputSchema: { factId: z.string() },
      handler: ({ factId }) => {
        const fact = getFact(store.current(), String(factId ?? ""));
        if (!fact) return error(`unknown factId: ${String(factId ?? "")}`);
        return ok({ fact });
      },
      annotations: { readOnlyHint: true },
    },
    {
      name: "kubetrail_list_sensitive_refs",
      description: "List sensitive refs and metadata. This never returns raw token, secret, kubeconfig, or credential material.",
      inputSchema: {},
      handler: () => ok({ sensitiveRefs: store.current().sensitiveRefs }),
      annotations: { readOnlyHint: true },
    },
    {
      name: "kubetrail_materialize_sensitive",
      description: "Return raw sensitive material for a sensitive:// ref. This is disabled unless KUBETRAIL_AGENT_ALLOW_MATERIALIZE=1.",
      inputSchema: { ref: z.string() },
      handler: ({ ref }) => {
        if (!config.allowMaterializeSensitive) {
          return error("materialization disabled; set KUBETRAIL_AGENT_ALLOW_MATERIALIZE=1 only in an authorized local workflow");
        }
        return ok({ ref, value: materialize(store.current(), String(ref ?? "")) });
      },
    },
    {
      name: "kubetrail_list_exp_templates",
      description: "List KubeTrail EXP template IDs available to the agent.",
      inputSchema: {},
      handler: () => ok({ templates: expTemplateIds }),
      annotations: { readOnlyHint: true },
    },
    {
      name: "kubetrail_generate_exp_plan",
      description: "Create a structured EXP generation plan. This does not write files or execute exploitation.",
      inputSchema: {
        templateId: z.enum(expTemplateIds as [string, ...string[]]),
        title: z.string(),
        findingIds: z.array(z.string()).optional(),
        parameters: z.record(z.string(), z.unknown()).optional(),
        sensitiveRefs: z.array(z.string()).optional(),
        preconditions: z.array(z.string()).optional(),
        sideEffects: z.array(z.string()).optional(),
        notes: z.array(z.string()).optional(),
      },
      handler: (args) => ok({ expRequest: args }),
      annotations: { readOnlyHint: true },
    },
  ];
}

function ok(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
  };
}

function error(message: string) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
  };
}
