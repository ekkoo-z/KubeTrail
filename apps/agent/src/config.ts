import { constants, existsSync } from "node:fs";
import { access, cp, mkdir, readdir, rm, stat } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const bundledContextRoot = resolve(here, "agent-context");
export const appRoot = existsSync(bundledContextRoot) ? resolve(resolveRuntimeDir(), "workspace") : resolve(here, "..");
export const repoRoot = existsSync(bundledContextRoot) ? appRoot : resolve(appRoot, "../..");

export type AgentProvider = "claude" | "codex";
export type AgentLanguage = "zh-CN" | "en-US";

export type McpServerConfig = {
  type?: "stdio" | "http" | "sse";
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  headers?: Record<string, string>;
  timeout?: number;
  alwaysLoad?: boolean;
};

export type AgentRuntimeConfig = {
  provider: AgentProvider;
  language: AgentLanguage;
  appRoot: string;
  repoRoot: string;
  runtimeDir: string;
  defaultInputPath: string;
  apiKey?: string;
  authToken?: string;
  model?: string;
  fallbackModel?: string;
  baseUrl?: string;
  apiKeyConfigured: boolean;
  authTokenConfigured: boolean;
  httpsProxy?: string;
  httpProxy?: string;
  noProxy?: string;
  timeoutMs: string;
  maxRetries: string;
  host: string;
  port: number;
  claudeConfigDir: string;
  codexHomeDir: string;
  pathToClaudeCodeExecutable?: string;
  pathToCodexExecutable?: string;
  enableGatewayModelDiscovery: boolean;
  allowMaterializeSensitive: boolean;
  maxTurns: number;
  maxBudgetUsd?: number;
  mcpServers: Record<string, McpServerConfig>;
};

export type AgentConfigOverrides = {
  provider?: AgentProvider;
  language?: AgentLanguage;
  apiKey?: string;
  authToken?: string;
  baseUrl?: string;
  model?: string;
  fallbackModel?: string;
  httpsProxy?: string;
  httpProxy?: string;
  noProxy?: string;
  timeoutMs?: string;
  maxRetries?: string;
  pathToClaudeCodeExecutable?: string;
  pathToCodexExecutable?: string;
  enableGatewayModelDiscovery?: boolean;
  allowMaterializeSensitive?: boolean;
  maxTurns?: number;
  maxBudgetUsd?: number;
  mcpServers?: Record<string, McpServerConfig>;
};

export function loadConfig(overrides: AgentConfigOverrides = {}): AgentRuntimeConfig {
  const defaultInputPath = resolveDefaultInputPath();
  const runtimeDir = resolveRuntimeDir();
  const provider = normalizeProvider(overrides.provider ?? firstNonEmpty("KUBETRAIL_AGENT_PROVIDER"));
  const port = numberEnv("KUBETRAIL_AGENT_PORT", 18080);
  const apiKey = stringOverride(overrides.apiKey) ?? providerApiKey(provider);
  const authToken = stringOverride(overrides.authToken) ?? providerAuthToken(provider);
  const baseUrl = stringOverride(overrides.baseUrl) ?? providerBaseUrl(provider);
  return {
    provider,
    language: normalizeLanguage(overrides.language ?? firstNonEmpty("KUBETRAIL_AGENT_LANGUAGE")),
    appRoot,
    repoRoot,
    runtimeDir,
    defaultInputPath,
    apiKey,
    authToken,
    model: stringOverride(overrides.model) ?? firstNonEmpty("KUBETRAIL_AGENT_MODEL") ?? defaultModel(),
    fallbackModel: stringOverride(overrides.fallbackModel) ?? firstNonEmpty("KUBETRAIL_AGENT_FALLBACK_MODEL"),
    baseUrl,
    apiKeyConfigured: Boolean(apiKey),
    authTokenConfigured: Boolean(authToken),
    httpsProxy: stringOverride(overrides.httpsProxy) ?? firstNonEmpty("KUBETRAIL_AGENT_HTTPS_PROXY"),
    httpProxy: stringOverride(overrides.httpProxy) ?? firstNonEmpty("KUBETRAIL_AGENT_HTTP_PROXY"),
    noProxy: stringOverride(overrides.noProxy) ?? firstNonEmpty("KUBETRAIL_AGENT_NO_PROXY"),
    timeoutMs: stringOverride(overrides.timeoutMs) ?? firstNonEmpty("KUBETRAIL_AGENT_TIMEOUT_MS", "API_TIMEOUT_MS") ?? "120000",
    maxRetries: stringOverride(overrides.maxRetries) ?? firstNonEmpty("KUBETRAIL_AGENT_MAX_RETRIES", "CLAUDE_CODE_MAX_RETRIES") ?? "2",
    host: firstNonEmpty("KUBETRAIL_AGENT_HOST") ?? "127.0.0.1",
    port,
    claudeConfigDir: resolve(firstNonEmpty("KUBETRAIL_AGENT_CONFIG_DIR", "CLAUDE_CONFIG_DIR") ?? resolve(runtimeDir, "claude")),
    codexHomeDir: resolveCodexHomeDir(provider, runtimeDir, apiKey, baseUrl),
    pathToClaudeCodeExecutable: stringOverride(overrides.pathToClaudeCodeExecutable) ?? firstNonEmpty("KUBETRAIL_AGENT_PATH_TO_CLAUDE"),
    pathToCodexExecutable: stringOverride(overrides.pathToCodexExecutable) ?? firstNonEmpty("KUBETRAIL_AGENT_PATH_TO_CODEX"),
    enableGatewayModelDiscovery: overrides.enableGatewayModelDiscovery ?? boolEnv("KUBETRAIL_AGENT_ENABLE_GATEWAY_MODEL_DISCOVERY", false),
    allowMaterializeSensitive: overrides.allowMaterializeSensitive ?? boolEnv("KUBETRAIL_AGENT_ALLOW_MATERIALIZE", false),
    maxTurns: numberOverride(overrides.maxTurns) ?? numberEnv("KUBETRAIL_AGENT_MAX_TURNS", 200),
    maxBudgetUsd: numberOverride(overrides.maxBudgetUsd) ?? optionalNumberEnv("KUBETRAIL_AGENT_MAX_BUDGET_USD"),
    mcpServers: overrides.mcpServers ?? parseMcpServers(firstNonEmpty("KUBETRAIL_AGENT_MCP_SERVERS")),
  };
}

export async function ensureRuntimeDirs(config: AgentRuntimeConfig, enabledSkills?: readonly string[]): Promise<void> {
  await mkdir(config.runtimeDir, { recursive: true });
  await syncBundledAgentContext(config);
  await mkdir(config.claudeConfigDir, { recursive: true });
  await mkdir(config.codexHomeDir, { recursive: true });
  if (config.pathToClaudeCodeExecutable) {
    await access(config.pathToClaudeCodeExecutable, constants.X_OK);
  }
  if (config.pathToCodexExecutable) {
    await access(config.pathToCodexExecutable, constants.X_OK);
  }
  if (config.provider === "codex") {
    await syncCodexSkills(config, enabledSkills);
  }
}

async function syncBundledAgentContext(config: AgentRuntimeConfig): Promise<void> {
  if (!existsSync(bundledContextRoot)) {
    return;
  }
  await mkdir(config.appRoot, { recursive: true });
  await copyOptionalFile(resolve(bundledContextRoot, "CLAUDE.md"), resolve(config.appRoot, "CLAUDE.md"));
  await copyOptionalFile(resolve(bundledContextRoot, "AGENTS.md"), resolve(config.appRoot, "AGENTS.md"));
  await copyOptionalDir(resolve(bundledContextRoot, "claude"), resolve(config.appRoot, ".claude"));
  await copyOptionalDir(resolve(bundledContextRoot, "exp", "assets"), resolve(config.appRoot, "exp", "assets"));
}

async function copyOptionalFile(source: string, target: string): Promise<void> {
  try {
    const info = await stat(source);
    if (!info.isFile()) {
      return;
    }
    await mkdir(dirname(target), { recursive: true });
    await cp(source, target, { force: true });
  } catch {
    // Optional bundled context is best-effort.
  }
}

async function copyOptionalDir(source: string, target: string): Promise<void> {
  try {
    const info = await stat(source);
    if (!info.isDirectory()) {
      return;
    }
    await mkdir(dirname(target), { recursive: true });
    await cp(source, target, { recursive: true, force: true });
  } catch {
    // Optional bundled context is best-effort.
  }
}

export function buildClaudeEnv(config: AgentRuntimeConfig, inputPath = ""): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { ...process.env };

  clearAmbientProxyEnv(env);
  clearAmbientModelEnv(env);
  setIfPresent(env, "ANTHROPIC_API_KEY", config.apiKey);
  setIfPresent(env, "ANTHROPIC_AUTH_TOKEN", config.authToken);
  setIfPresent(env, "ANTHROPIC_BASE_URL", config.baseUrl);
  setClaudeModelEnv(env, config.model);
  setIfPresent(env, "HTTPS_PROXY", config.httpsProxy);
  setIfPresent(env, "HTTP_PROXY", config.httpProxy);
  setIfPresent(env, "NO_PROXY", config.noProxy);
  if (inputPath.trim()) {
    setIfPresent(env, "KUBETRAIL_RESULT_PATH", inputPath);
    delete env.KUBETRAIL_DISABLE_DEFAULT_RESULT;
  } else {
    delete env.KUBETRAIL_RESULT_PATH;
    env.KUBETRAIL_DISABLE_DEFAULT_RESULT = "1";
  }
  env.KUBETRAIL_AGENT_LANGUAGE = config.language;

  env.API_TIMEOUT_MS = config.timeoutMs;
  env.CLAUDE_CODE_MAX_RETRIES = config.maxRetries;
  if (shouldUseIsolatedClaudeConfig(config)) {
    env.CLAUDE_CONFIG_DIR = config.claudeConfigDir;
  } else {
    delete env.CLAUDE_CONFIG_DIR;
  }
  env.CLAUDE_AGENT_SDK_CLIENT_APP = "kubetrail-agent/0.1.0";

  if (config.enableGatewayModelDiscovery) {
    env.CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY = "1";
  }

  env.DISABLE_TELEMETRY ??= "1";
  env.DISABLE_ERROR_REPORTING ??= "1";
  env.DISABLE_AUTOUPDATER ??= "1";
  env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC ??= "1";
  env.CLAUDE_CODE_DISABLE_AUTO_MEMORY ??= "1";
  return env;
}

export function buildCodexEnv(config: AgentRuntimeConfig, inputPath = ""): Record<string, string> {
  const env: Record<string, string | undefined> = { ...process.env };

  clearAmbientProxyEnv(env);
  if (shouldUseIsolatedCodexHome(config)) {
    setIfPresent(env, "CODEX_HOME", config.codexHomeDir);
  } else {
    delete env.CODEX_HOME;
  }
  setIfPresent(env, "CODEX_API_KEY", config.apiKey);
  setIfPresent(env, "OPENAI_API_KEY", config.apiKey);
  setIfPresent(env, "HTTPS_PROXY", config.httpsProxy);
  setIfPresent(env, "HTTP_PROXY", config.httpProxy);
  setIfPresent(env, "NO_PROXY", config.noProxy);
  if (inputPath.trim()) {
    setIfPresent(env, "KUBETRAIL_RESULT_PATH", inputPath);
    delete env.KUBETRAIL_DISABLE_DEFAULT_RESULT;
  } else {
    delete env.KUBETRAIL_RESULT_PATH;
    env.KUBETRAIL_DISABLE_DEFAULT_RESULT = "1";
  }
  env.KUBETRAIL_AGENT_LANGUAGE = config.language;
  if (config.allowMaterializeSensitive) {
    env.KUBETRAIL_AGENT_ALLOW_MATERIALIZE = "1";
  } else {
    delete env.KUBETRAIL_AGENT_ALLOW_MATERIALIZE;
  }
  env.DISABLE_TELEMETRY ??= "1";
  env.DISABLE_ERROR_REPORTING ??= "1";

  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

function clearAmbientProxyEnv(env: Record<string, string | undefined>): void {
  for (const name of ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "no_proxy", "all_proxy"]) {
    delete env[name];
  }
}

function shouldUseIsolatedClaudeConfig(config: AgentRuntimeConfig): boolean {
  return Boolean(
    config.apiKey ||
      config.authToken ||
      config.baseUrl ||
      firstNonEmpty("KUBETRAIL_AGENT_CONFIG_DIR", "CLAUDE_CONFIG_DIR"),
  );
}

function shouldUseIsolatedCodexHome(config: AgentRuntimeConfig): boolean {
  return Boolean(
    config.apiKey ||
      config.baseUrl ||
      firstNonEmpty("KUBETRAIL_AGENT_CODEX_HOME", "CODEX_HOME"),
  );
}

function clearAmbientModelEnv(env: Record<string, string | undefined>): void {
  for (const name of [
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_REASONING_MODEL",
  ]) {
    delete env[name];
  }
}

function setClaudeModelEnv(env: Record<string, string | undefined>, model?: string): void {
  const value = stringOverride(model);
  if (!value) {
    return;
  }
  env.ANTHROPIC_MODEL = value;
  env.ANTHROPIC_DEFAULT_OPUS_MODEL = value;
  env.ANTHROPIC_DEFAULT_SONNET_MODEL = value;
  env.ANTHROPIC_DEFAULT_HAIKU_MODEL = value;
  env.ANTHROPIC_REASONING_MODEL = value;
}

export function publicConfig(config: AgentRuntimeConfig): Record<string, unknown> {
  return {
    provider: config.provider,
    language: config.language,
    defaultInputPath: config.defaultInputPath,
    model: config.model ?? "(sdk default)",
    fallbackModel: config.fallbackModel ?? "",
    baseUrl: config.baseUrl ?? (config.provider === "codex" ? "(OpenAI default)" : "(Anthropic default)"),
    apiKeyConfigured: config.apiKeyConfigured,
    authTokenConfigured: config.authTokenConfigured,
    httpsProxyConfigured: Boolean(config.httpsProxy),
    httpProxyConfigured: Boolean(config.httpProxy),
    noProxy: config.noProxy ?? "",
    timeoutMs: config.timeoutMs,
    maxRetries: config.maxRetries,
    runtimeDir: config.runtimeDir,
    claudeConfigDir: config.claudeConfigDir,
    codexHomeDir: config.codexHomeDir,
    claudeExecutableConfigured: Boolean(config.pathToClaudeCodeExecutable),
    codexExecutableConfigured: Boolean(config.pathToCodexExecutable),
    enableGatewayModelDiscovery: config.enableGatewayModelDiscovery,
    allowMaterializeSensitive: config.allowMaterializeSensitive,
    maxTurns: config.maxTurns,
    maxBudgetUsd: config.maxBudgetUsd,
    mcpServers: Object.keys(config.mcpServers),
  };
}

export async function listSkillNamesForProvider(config: AgentRuntimeConfig): Promise<string[]> {
  const root = config.provider === "codex" ? resolve(config.appRoot, ".agents", "skills") : resolve(config.appRoot, ".claude", "skills");
  try {
    const entries = await readdir(root, { withFileTypes: true });
    const names: string[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const skillFile = join(root, entry.name, "SKILL.md");
      try {
        const info = await stat(skillFile);
        if (info.isFile()) {
          names.push(entry.name);
        }
      } catch {
        // Ignore incomplete skill directories.
      }
    }
    return names.sort();
  } catch {
    return [];
  }
}

export function resolveRuntimeDir(): string {
  return resolve(firstNonEmpty("KUBETRAIL_AGENT_RUNTIME_DIR") ?? defaultRuntimeDir());
}

function resolveCodexHomeDir(provider: AgentProvider, runtimeDir: string, apiKey?: string, baseUrl?: string): string {
  const explicitHome = firstNonEmpty("KUBETRAIL_AGENT_CODEX_HOME", "CODEX_HOME");
  if (explicitHome) {
    return resolve(explicitHome);
  }
  if (provider === "codex" && !apiKey && !baseUrl) {
    return resolve(homedir(), ".codex");
  }
  return resolve(runtimeDir, "codex");
}

function defaultRuntimeDir(): string {
  const home = homedir();
  const os = platform();
  if (os === "darwin") {
    return resolve(home, "Library/Application Support/KubeTrail/runtime");
  }
  if (os === "win32") {
    return resolve(process.env.APPDATA || resolve(home, "AppData/Roaming"), "KubeTrail/runtime");
  }
  return resolve(process.env.XDG_DATA_HOME || resolve(home, ".local/share"), "kubetrail/runtime");
}

function resolveDefaultInputPath(): string {
  const explicit = firstNonEmpty("KUBETRAIL_RESULT_PATH");
  if (explicit) {
    return resolve(explicit);
  }
  if (boolEnv("KUBETRAIL_DISABLE_DEFAULT_RESULT", false)) {
    return "";
  }
  const dbus = resolve(repoRoot, "dbus.json");
  if (existsSync(dbus)) {
    return dbus;
  }
  const result = resolve(repoRoot, "result.json");
  if (existsSync(result)) {
    return result;
  }
  return dbus;
}

function firstNonEmpty(...names: string[]): string | undefined {
  for (const name of names) {
    const value = process.env[name];
    if (value && value.trim() !== "") {
      return value;
    }
  }
  return undefined;
}

function normalizeProvider(value?: string): AgentProvider {
  const normalized = (value ?? "").trim().toLowerCase();
  if (normalized === "codex") {
    return "codex";
  }
  return "claude";
}

function normalizeLanguage(value?: string): AgentLanguage {
  const normalized = (value ?? "").trim().toLowerCase();
  if (normalized === "en" || normalized === "en-us") {
    return "en-US";
  }
  return "zh-CN";
}

function defaultModel(): string {
  return "";
}

function providerApiKey(provider: AgentProvider): string | undefined {
  if (provider === "codex") {
    return firstNonEmpty("KUBETRAIL_AGENT_API_KEY", "KUBETRAIL_AGENT_OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_API_KEY");
  }
  return firstNonEmpty("KUBETRAIL_AGENT_API_KEY", "ANTHROPIC_API_KEY");
}

function providerAuthToken(provider: AgentProvider): string | undefined {
  if (provider === "codex") {
    return undefined;
  }
  return firstNonEmpty("KUBETRAIL_AGENT_AUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN");
}

function providerBaseUrl(provider: AgentProvider): string | undefined {
  if (provider === "codex") {
    return firstNonEmpty("KUBETRAIL_AGENT_BASE_URL", "KUBETRAIL_AGENT_OPENAI_BASE_URL", "OPENAI_BASE_URL");
  }
  return firstNonEmpty("KUBETRAIL_AGENT_BASE_URL", "ANTHROPIC_BASE_URL");
}

async function syncCodexSkills(config: AgentRuntimeConfig, enabledSkills?: readonly string[]): Promise<void> {
  const sourceRoot = resolve(config.appRoot, ".claude", "skills");
  const targetRoot = resolve(config.appRoot, ".agents", "skills");
  let entries;
  try {
    entries = await readdir(sourceRoot, { withFileTypes: true });
  } catch {
    return;
  }
  await mkdir(targetRoot, { recursive: true });
  const sourceNames = new Set(entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name));
  const enabledSet = enabledSkills?.length ? new Set(enabledSkills) : undefined;
  if (enabledSet) {
    try {
      const targetEntries = await readdir(targetRoot, { withFileTypes: true });
      await Promise.all(targetEntries.map(async (entry) => {
        if (!entry.isDirectory() || !sourceNames.has(entry.name) || enabledSet.has(entry.name)) {
          return;
        }
        await rm(join(targetRoot, entry.name), { recursive: true, force: true });
      }));
    } catch {
      // Stale generated skills should not prevent the agent from starting.
    }
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || !validLocalName(entry.name)) {
      continue;
    }
    if (enabledSet && !enabledSet.has(entry.name)) {
      continue;
    }
    const source = join(sourceRoot, entry.name, "SKILL.md");
    const targetDir = join(targetRoot, entry.name);
    const target = join(targetDir, "SKILL.md");
    try {
      const info = await stat(source);
      if (!info.isFile()) {
        continue;
      }
      await mkdir(targetDir, { recursive: true });
      await cp(source, target, { force: true });
    } catch {
      // A broken skill should not prevent the agent from starting.
    }
  }
}

function validLocalName(name: string): boolean {
  return /^[A-Za-z0-9_-]{1,80}$/.test(name);
}

function stringOverride(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function numberOverride(value: number | undefined): number | undefined {
  return value !== undefined && Number.isFinite(value) ? value : undefined;
}

function setIfPresent(env: Record<string, string | undefined>, name: string, value?: string): void {
  if (value && value.trim() !== "") {
    env[name] = value;
  }
}

function boolEnv(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function numberEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function optionalNumberEnv(name: string): number | undefined {
  const value = process.env[name];
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseMcpServers(value: string | undefined): Record<string, McpServerConfig> {
  if (!value) {
    return {};
  }
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {};
  }
  const out: Record<string, McpServerConfig> = {};
  for (const [name, config] of Object.entries(parsed as Record<string, unknown>)) {
    if (!validMcpName(name) || !config || typeof config !== "object" || Array.isArray(config)) {
      continue;
    }
    const normalized = normalizeMcpServerConfig(config as Record<string, unknown>);
    if (normalized) {
      out[name] = normalized;
    }
  }
  return out;
}

function normalizeMcpServerConfig(config: Record<string, unknown>): McpServerConfig | undefined {
  const type = typeof config.type === "string" ? config.type : "stdio";
  const timeout = typeof config.timeout === "number" && Number.isFinite(config.timeout) ? config.timeout : undefined;
  const alwaysLoad = typeof config.alwaysLoad === "boolean" ? config.alwaysLoad : undefined;
  if (type === "http" || type === "sse") {
    if (typeof config.url !== "string" || config.url.trim() === "") {
      return undefined;
    }
    return {
      type,
      url: config.url.trim(),
      headers: stringRecord(config.headers),
      timeout,
      alwaysLoad,
    };
  }
  if (type === "stdio") {
    if (typeof config.command !== "string" || config.command.trim() === "") {
      return undefined;
    }
    return {
      type: "stdio",
      command: config.command.trim(),
      args: stringArray(config.args),
      env: stringRecord(config.env),
      timeout,
      alwaysLoad,
    };
  }
  return undefined;
}

function validMcpName(name: string): boolean {
  return /^[A-Za-z0-9_-]{1,80}$/.test(name);
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const out = value.map((item) => String(item).trim()).filter(Boolean);
  return out.length ? out : undefined;
}

function stringRecord(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const out: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    const k = key.trim();
    const v = String(raw).trim();
    if (k && v) {
      out[k] = v;
    }
  }
  return Object.keys(out).length ? out : undefined;
}
