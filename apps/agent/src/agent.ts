import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { query, type CanUseTool, type Options, type SDKMessage, type SDKResultMessage, type Settings } from "@anthropic-ai/claude-agent-sdk";
import { Codex, type CodexOptions, type ThreadEvent, type ThreadItem } from "@openai/codex-sdk";
import {
  buildClaudeEnv,
  buildCodexEnv,
  ensureRuntimeDirs,
  listSkillNamesForProvider,
  loadConfig,
  type AgentConfigOverrides,
  type AgentRuntimeConfig,
  type McpServerConfig,
} from "./config.js";
import { KubeTrailContextStore } from "./context.js";
import { createKubeTrailMcpServer, kubeTrailToolNames } from "./tools/kubetrail.js";

export type AgentEvent =
  | { type: "init"; sessionId: string; model: string; tools: string[]; skills: string[]; provider?: string }
  | { type: "assistant"; text: string; error?: string }
  | { type: "tool_use"; toolName: string; toolInput: Record<string, unknown>; skillName?: string }
  | { type: "result"; sessionId: string; success: boolean; text: string; costUsd?: number; turns?: number }
  | { type: "system"; subtype?: string; text: string }
  | { type: "stderr"; text: string }
  | { type: "error"; message: string };

export type RunAgentParams = {
  message: string;
  inputPath?: string;
  resumeSession?: string;
  forkSession?: boolean;
  useDefaultInputPath?: boolean;
  config?: AgentConfigOverrides;
  abortController?: AbortController;
  onEvent?: (event: AgentEvent) => void;
};

export type RunAgentResult = {
  sessionId?: string;
  text: string;
  result?: SDKResultMessage;
};

export async function runKubeTrailAgent(params: RunAgentParams): Promise<RunAgentResult> {
  const config = loadConfig(params.config);
  await ensureRuntimeDirs(config);
  if (config.provider === "codex") {
    return runKubeTrailCodexAgent(config, params);
  }
  return runKubeTrailClaudeAgent(config, params);
}

async function runKubeTrailClaudeAgent(config: AgentRuntimeConfig, params: RunAgentParams): Promise<RunAgentResult> {
  const explicitInputPath = params.inputPath?.trim() ?? "";
  const inputPath = explicitInputPath || (params.useDefaultInputPath ? config.defaultInputPath : "");
  const store = new KubeTrailContextStore(inputPath);
  const mcpServers = {
    kubetrail: createKubeTrailMcpServer(store, config),
    ...config.mcpServers,
  };
  const isResume = Boolean(params.resumeSession);
  const prompt = buildPrompt(params.message, inputPath, isResume);
  const options = buildOptions(config, mcpServers, params, inputPath);

  let sessionId: string | undefined;
  let result: SDKResultMessage | undefined;
  const chunks: string[] = [];
  let lastAssistantText = "";

  try {
    for await (const message of query({ prompt, options })) {
      // Emit tool_use events before the main event so UI can show tool activity
      if (message.type === "assistant") {
        for (const tool of extractToolUses(message.message.content)) {
          const input = tool.input as Record<string, unknown> | undefined;
          const isSkillCall = tool.name === "Skill";
          const skillName = isSkillCall ? String(input?.skill ?? input?.args ?? "") : undefined;
          params.onEvent?.({
            type: "tool_use",
            toolName: tool.name,
            toolInput: (input ?? {}) as Record<string, unknown>,
            skillName: skillName || undefined,
          });
        }
      }
      const event = toEvent(message);
      if (event) {
        if (event.type === "assistant") {
          if (isDuplicateAssistantText(event.text, lastAssistantText)) {
            continue;
          }
          lastAssistantText = event.text;
          chunks.push(event.text);
        }
        params.onEvent?.(event);
        if ("sessionId" in event) {
          sessionId = event.sessionId;
        }
      }
      if (message.type === "result") {
        result = message;
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    params.onEvent?.({ type: "error", message });
    throw error;
  }

  const resultText = result
    ? result.subtype === "success"
      ? result.result
      : result.errors.join("\n")
    : chunks.join("\n").trim();

  return { sessionId, text: resultText, result };
}

function buildOptions(config: AgentRuntimeConfig, mcpServers: Options["mcpServers"], params: RunAgentParams, inputPath: string): Options {
  const canUseTool: CanUseTool = async (_toolName) => {
    return { behavior: "allow" };
  };

  return {
    cwd: config.appRoot,
    env: buildClaudeEnv(config, inputPath),
    model: config.model || undefined,
    fallbackModel: config.fallbackModel || undefined,
    settings: buildFlagSettings(config),
    abortController: params.abortController,
    pathToClaudeCodeExecutable: config.pathToClaudeCodeExecutable,
    mcpServers,
    tools: [],
    allowedTools: buildAllowedTools(mcpServers),
    canUseTool,
    permissionMode: "dontAsk",
    settingSources: ["project"],
    skills: "all",
    resume: params.resumeSession || undefined,
    forkSession: params.resumeSession && params.forkSession ? true : undefined,
    maxTurns: config.maxTurns,
    maxBudgetUsd: config.maxBudgetUsd,
    stderr: (data) => params.onEvent?.({ type: "stderr", text: data }),
  };
}

function buildFlagSettings(config: AgentRuntimeConfig): Settings | undefined {
  const model = config.model?.trim();
  if (!model) {
    return undefined;
  }

  const settings: Settings = {
    model,
    env: {
      ANTHROPIC_MODEL: model,
      ANTHROPIC_DEFAULT_OPUS_MODEL: model,
      ANTHROPIC_DEFAULT_SONNET_MODEL: model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: model,
      ANTHROPIC_REASONING_MODEL: model,
    },
  };
  const aliases = modelOverrideAliases(model);
  if (aliases.length > 0) {
    settings.availableModels = [model, ...aliases];
    settings.modelOverrides = Object.fromEntries(aliases.map((alias) => [alias, model]));
  }
  return settings;
}

function modelOverrideAliases(model: string): string[] {
  const stripped = stripGatewayModelSuffix(model);
  if (stripped === model) {
    return [];
  }
  const aliases = new Set<string>([stripped]);
  const unprefixed = stripped.split("/").pop()?.trim();
  if (unprefixed) {
    aliases.add(unprefixed);
  }
  return [...aliases];
}

function stripGatewayModelSuffix(model: string): string {
  return model.replace(/\[[^\]]+\]$/, "");
}

function buildAllowedTools(mcpServers: Options["mcpServers"]): string[] {
  const allowed = new Set<string>([
    "Skill",
    ...kubeTrailToolNames(),
  ]);
  for (const name of Object.keys(mcpServers ?? {})) {
    if (/^[A-Za-z0-9_-]{1,80}$/.test(name)) {
      allowed.add(`mcp__${name}__*`);
    }
  }
  return [...allowed];
}

function buildPrompt(message: string, inputPath: string, isResume: boolean): string {
  const responseRules = [
    "全程使用简体中文回答，除非用户明确要求其他语言。",
    "不要输出过程性自述、工具调用前自言自语或英文 filler，例如 `Let me read...`、`Now I have...`、`Let me generate...`。",
    "只输出面向用户的结论、证据、攻击路径、下一步行动和必要的缺口说明。",
  ];
  if (isResume) {
    return [...responseRules, "", `用户问题: ${message}`].join("\n");
  }
  if (!inputPath) {
    return [
      ...responseRules,
      "当前没有加载 KubeTrail 扫描结果。",
      "如果用户的问题可以通过当前上下文或其它已配置 MCP 工具回答，可以直接继续；不要为了非扫描任务主动调用 kubetrail_load_result。",
      "不要声称已经观察到任何 factId、权限、Pod、Node、Namespace、云账号或 sensitiveRef；涉及目标环境结论时必须明确缺少当前扫描证据。",
      "",
      `用户问题: ${message}`,
    ].join("\n");
  }
  return [
    ...responseRules,
    `先调用 kubetrail_load_result 加载: ${inputPath}`,
    "然后基于已加载证据回答用户问题。",
    "不要编造 factId、权限、Pod、Node、Namespace、云账号或 sensitiveRef。",
    "如果需要生成利用方向，只输出计划和模板选择，不执行有副作用动作。",
    "",
    `用户问题: ${message}`,
  ].join("\n");
}

function toEvent(message: SDKMessage): AgentEvent | undefined {
  if (message.type === "system" && message.subtype === "init") {
    return {
      type: "init",
      sessionId: message.session_id,
      model: message.model,
      tools: message.tools,
      skills: message.skills,
      provider: "claude",
    };
  }
  if (message.type === "assistant") {
    const text = extractAssistantText(message.message.content);
    const error = message.error;
    if (error) {
      return { type: "assistant", text: text || `[assistant error: ${error}]`, error };
    }
    return text ? { type: "assistant", text } : undefined;
  }
  if (message.type === "result") {
    return {
      type: "result",
      sessionId: message.session_id,
      success: message.subtype === "success",
      text: message.subtype === "success" ? message.result : message.errors.join("\n"),
      costUsd: message.total_cost_usd,
      turns: message.num_turns,
    };
  }
  if (message.type === "system") {
    const subtype = "subtype" in message ? String(message.subtype) : undefined;
    if (subtype === "thinking_tokens" || subtype === "commands_changed") {
      return undefined;
    }
    if (subtype === "permission_denied") {
      const denied = message as { tool_name?: string; decision_reason_type?: string };
      return { type: "system", subtype, text: `permission denied: tool=${denied.tool_name ?? "?"} reason=${denied.decision_reason_type ?? "?"}` };
    }
    if (subtype === "api_retry") {
      const retry = message as { error_status?: number | null; error?: string; attempt?: number; max_retries?: number };
      return { type: "system", subtype, text: `API retry ${retry.attempt ?? "?"}/${retry.max_retries ?? "?"}: status=${retry.error_status ?? "?"} error=${retry.error ?? "?"}` };
    }
    if (subtype === "status") {
      const status = message as { status?: string | null; compact_error?: string };
      return { type: "system", subtype, text: `status: ${status.status ?? "idle"}${status.compact_error ? ` compact_error=${status.compact_error}` : ""}` };
    }
    return { type: "system", subtype, text: JSON.stringify(message) };
  }
  if (message.type === "auth_status") {
    const auth = message as { error?: string; output?: string[]; isAuthenticating?: boolean };
    if (auth.error) {
      return { type: "error", message: `auth: ${auth.error}` };
    }
    if (auth.isAuthenticating) {
      return { type: "system", subtype: "auth", text: "authenticating..." };
    }
    return undefined;
  }
  if (message.type === "rate_limit_event") {
    const info = (message as { rate_limit_info?: Record<string, unknown> }).rate_limit_info;
    return { type: "system", subtype: "rate_limit", text: `rate limited: ${JSON.stringify(info)}` };
  }
  return undefined;
}

async function runKubeTrailCodexAgent(config: AgentRuntimeConfig, params: RunAgentParams): Promise<RunAgentResult> {
  const explicitInputPath = params.inputPath?.trim() ?? "";
  const inputPath = explicitInputPath || (params.useDefaultInputPath ? config.defaultInputPath : "");
  const prompt = buildPrompt(params.message, inputPath, Boolean(params.resumeSession));
  const skills = await listSkillNamesForProvider(config);
  const tools = buildCodexToolList(config);
  const codex = new Codex({
    codexPathOverride: config.pathToCodexExecutable,
    apiKey: config.apiKey,
    baseUrl: config.baseUrl,
    env: buildCodexEnv(config, inputPath),
    config: buildCodexConfig(config, inputPath),
  });
  const threadOptions = {
    model: config.model || undefined,
    sandboxMode: "read-only" as const,
    workingDirectory: config.appRoot,
    skipGitRepoCheck: true,
    networkAccessEnabled: false,
    webSearchMode: "disabled" as const,
    approvalPolicy: "never" as const,
  };
  const thread = params.resumeSession
    ? codex.resumeThread(params.resumeSession, threadOptions)
    : codex.startThread(threadOptions);

  let sessionId = params.resumeSession || undefined;
  let finalText = "";
  let sawInit = false;
  const { events } = await thread.runStreamed(prompt, { signal: params.abortController?.signal });

  try {
    for await (const event of events) {
      if (event.type === "thread.started") {
        sessionId = event.thread_id;
        sawInit = true;
        params.onEvent?.({
          type: "init",
          sessionId,
          model: config.model || "(codex default)",
          tools,
          skills,
          provider: "codex",
        });
        continue;
      }
      if (!sawInit && sessionId) {
        sawInit = true;
        params.onEvent?.({
          type: "init",
          sessionId,
          model: config.model || "(codex default)",
          tools,
          skills,
          provider: "codex",
        });
      }
      const mapped = codexEventToAgentEvents(event);
      for (const agentEvent of mapped) {
        if (agentEvent.type === "assistant") {
          finalText = agentEvent.text;
        }
        params.onEvent?.(agentEvent);
      }
      if (event.type === "turn.failed") {
        throw new Error(event.error.message);
      }
      if (event.type === "error") {
        throw new Error(event.message);
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    params.onEvent?.({ type: "error", message });
    throw error;
  }

  params.onEvent?.({
    type: "result",
    sessionId: sessionId ?? "",
    success: true,
    text: finalText,
  });
  return { sessionId, text: finalText };
}

function codexEventToAgentEvents(event: ThreadEvent): AgentEvent[] {
  if (event.type === "item.started" || event.type === "item.updated" || event.type === "item.completed") {
    return codexItemToAgentEvents(event.item, event.type);
  }
  if (event.type === "turn.failed") {
    return [{ type: "error", message: event.error.message }];
  }
  if (event.type === "error") {
    return [{ type: "error", message: event.message }];
  }
  return [];
}

function codexItemToAgentEvents(item: ThreadItem, eventType: "item.started" | "item.updated" | "item.completed"): AgentEvent[] {
  if (item.type === "agent_message" && eventType === "item.completed" && item.text.trim()) {
    return [{ type: "assistant", text: item.text.trim() }];
  }
  if (item.type === "mcp_tool_call" && eventType === "item.started") {
    return [{
      type: "tool_use",
      toolName: `mcp__${item.server}__${item.tool}`,
      toolInput: (item.arguments && typeof item.arguments === "object" ? item.arguments : {}) as Record<string, unknown>,
    }];
  }
  if (item.type === "mcp_tool_call" && eventType === "item.completed" && item.status === "failed") {
    if (isCodexMcpUserCancellation(item)) {
      return [];
    }
    return [{ type: "system", subtype: "mcp_tool_failed", text: `${item.server}.${item.tool}: ${item.error?.message ?? "failed"}` }];
  }
  if (item.type === "command_execution" && eventType === "item.completed") {
    if (item.status === "completed") {
      return [];
    }
    return [{ type: "system", subtype: "command", text: `command ${item.status}: ${item.command}` }];
  }
  if (item.type === "error" && eventType === "item.completed") {
    return [{ type: "error", message: item.message }];
  }
  return [];
}

function isCodexMcpUserCancellation(item: ThreadItem): boolean {
  if (item.type !== "mcp_tool_call") {
    return false;
  }
  const message = item.error?.message?.trim() ?? "";
  return /^user cancelled MCP tool call$/i.test(message) || /^user canceled MCP tool call$/i.test(message);
}

function buildCodexConfig(config: AgentRuntimeConfig, inputPath: string): CodexOptions["config"] {
  return {
    mcp_servers: buildCodexMcpServers(config, inputPath),
  } as CodexOptions["config"];
}

function buildCodexMcpServers(config: AgentRuntimeConfig, inputPath: string): Record<string, unknown> {
  const servers: Record<string, unknown> = {
    kubetrail: buildKubeTrailCodexMcpServer(config, inputPath),
  };
  for (const [name, server] of Object.entries(config.mcpServers)) {
    const converted = convertCodexMcpServer(server);
    if (converted) {
      servers[name] = converted;
    }
  }
  return servers;
}

function buildKubeTrailCodexMcpServer(config: AgentRuntimeConfig, inputPath: string): Record<string, unknown> {
  const command = currentAgentMcpCommand(config);
  const env: Record<string, string> = {
    KUBETRAIL_AGENT_ALLOW_MATERIALIZE: config.allowMaterializeSensitive ? "1" : "0",
  };
  if (inputPath.trim()) {
    env.KUBETRAIL_RESULT_PATH = inputPath;
  } else {
    env.KUBETRAIL_DISABLE_DEFAULT_RESULT = "1";
  }
  return {
    command: command.command,
    args: command.args,
    cwd: config.appRoot,
    enabled: true,
    required: true,
    startup_timeout_sec: 20,
    tool_timeout_sec: 60,
    default_tools_approval_mode: "approve",
    enabled_tools: kubeTrailToolNames().filter((name) => !name.startsWith("mcp__")),
    env,
  };
}

function currentAgentMcpCommand(config: AgentRuntimeConfig): { command: string; args: string[] } {
  const entry = process.argv[1] ?? "";
  if (entry.endsWith(".mjs") || entry.endsWith(".js")) {
    return { command: process.execPath, args: [entry, "mcp"] };
  }
  const distCli = resolve(config.appRoot, "dist", "cli.js");
  if (existsSync(distCli)) {
    return { command: process.execPath, args: [distCli, "mcp"] };
  }
  return { command: "npx", args: ["tsx", "src/cli.ts", "mcp"] };
}

function convertCodexMcpServer(server: McpServerConfig): Record<string, unknown> | undefined {
  const timeout = typeof server.timeout === "number" && Number.isFinite(server.timeout) && server.timeout > 0
    ? Math.ceil(server.timeout / 1000)
    : undefined;
  if (server.type === "http" || server.type === "sse") {
    if (!server.url) return undefined;
    return {
      url: server.url,
      enabled: true,
      default_tools_approval_mode: "approve",
      ...(server.headers ? { http_headers: server.headers } : {}),
      ...(timeout ? { tool_timeout_sec: timeout } : {}),
    };
  }
  if (!server.command) return undefined;
  return {
    command: server.command,
    ...(server.args ? { args: server.args } : {}),
    ...(server.env ? { env: server.env } : {}),
    enabled: true,
    default_tools_approval_mode: "approve",
    ...(timeout ? { tool_timeout_sec: timeout } : {}),
  };
}

function buildCodexToolList(config: AgentRuntimeConfig): string[] {
  const names = new Set<string>(kubeTrailToolNames());
  for (const name of Object.keys(config.mcpServers)) {
    names.add(`mcp__${name}__*`);
  }
  return [...names];
}

function extractAssistantText(content: unknown): string {
  if (!Array.isArray(content)) {
    return "";
  }
  const out: string[] = [];
  for (const block of content) {
    if (block && typeof block === "object" && "type" in block && (block as { type?: string }).type === "text") {
      const text = (block as { text?: unknown }).text;
      if (typeof text === "string") {
        out.push(text);
      }
    }
  }
  return out.join("\n").trim();
}

function isDuplicateAssistantText(text: string, previous: string): boolean {
  if (!previous) {
    return false;
  }
  return normalizeAssistantText(text) === normalizeAssistantText(previous);
}

function normalizeAssistantText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function extractToolUses(content: unknown): Array<{ name: string; input: unknown }> {
  if (!Array.isArray(content)) return [];
  return content
    .filter((block): block is Record<string, unknown> =>
      Boolean(block) && typeof block === "object" && (block as { type?: string }).type === "tool_use"
    )
    .map((block) => ({
      name: String(block.name ?? ""),
      input: block.input,
    }))
    .filter((tool) => tool.name !== "");
}
