import { loadConfig, publicConfig } from "./config.js";
import { runKubeTrailAgent } from "./agent.js";
import { runPipe } from "./pipe.js";
import { listExpTemplates, renderExpBundle } from "./exp/render.js";
import { runKubeTrailMcpStdio } from "./tools/kubetrail.js";

type ParsedArgs = {
  command: string;
  flags: Record<string, string | boolean | string[]>;
  rest: string[];
};

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  switch (args.command) {
    case "chat":
      await runChat(args);
      return;
    case "pipe":
      await runPipe();
      return;
    case "exp":
      await runExp(args);
      return;
    case "env":
      console.log(JSON.stringify(publicConfig(loadConfig()), null, 2));
      return;
    case "mcp":
      await runKubeTrailMcpStdio(loadConfig());
      return;
    default:
      usage();
      process.exitCode = 2;
  }
}

async function runChat(args: ParsedArgs): Promise<void> {
  const message = stringFlag(args, "message") ?? (args.rest.join(" ") || "分析当前 KubeTrail 结果，列出危险点、证据和建议的验证方向。");
  const input = stringFlag(args, "input");
  const session = stringFlag(args, "session");
  const json = Boolean(args.flags.json);
  const result = await runKubeTrailAgent({
    message,
    inputPath: input,
    useDefaultInputPath: false,
    resumeSession: session,
    config: {
      provider: providerFlag(args),
    },
    onEvent: (event) => {
      if (json) {
        console.log(JSON.stringify(event));
        return;
      }
      if (event.type === "assistant") {
        console.log(event.text);
      } else if (event.type === "init") {
        console.error(`[session ${event.sessionId}] model=${event.model}`);
      } else if (event.type === "result") {
        console.error(`[done] session=${event.sessionId} turns=${event.turns ?? 0} cost=${event.costUsd ?? 0}`);
      } else if (event.type === "error") {
        console.error(`[error] ${event.message}`);
      }
    },
  });
  if (json) {
    console.log(JSON.stringify({ type: "final", sessionId: result.sessionId, text: result.text }));
  }
}


async function runExp(args: ParsedArgs): Promise<void> {
  const subcommand = args.rest[0] ?? "list";
  const json = Boolean(args.flags.json);
  if (subcommand === "list") {
    const templates = listExpTemplates();
    if (json) {
      console.log(JSON.stringify({ templates }, null, 2));
      return;
    }
    for (const template of templates) {
      console.log(`${template.templateId}\t${template.kind}\t${template.mode}\t${template.title}`);
    }
    return;
  }

  if (subcommand === "render") {
    const templateId = stringFlag(args, "template") ?? args.rest[1];
    if (!templateId) {
      throw new Error("exp render requires --template <templateId>");
    }
    const params = parseExpParams(args);
    const result = await renderExpBundle({
      templateId,
      outDir: stringFlag(args, "out"),
      params,
      findingIds: splitList(stringFlag(args, "finding-ids")),
      factIds: splitList(stringFlag(args, "fact-ids")),
      sensitiveRefs: splitList(stringFlag(args, "sensitive-refs")),
    });
    if (json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    console.log(`EXP bundle: ${result.bundleDir}`);
    console.log(`Template: ${result.template.templateId} (${result.template.kind}, ${result.template.mode})`);
    console.log("Run:");
    for (const command of result.runCommands) {
      console.log(`  ${command}`);
    }
    if (result.cleanupCommands.length) {
      console.log("Cleanup:");
      for (const command of result.cleanupCommands) {
        console.log(`  ${command}`);
      }
    }
    return;
  }

  throw new Error(`unknown exp subcommand: ${subcommand}`);
}

function parseArgs(values: string[]): ParsedArgs {
  const command = values[0] ?? "";
  const flags: Record<string, string | boolean | string[]> = {};
  const rest: string[] = [];
  for (let i = 1; i < values.length; i++) {
    const value = values[i];
    if (value.startsWith("--")) {
      const key = value.slice(2);
      const next = values[i + 1];
      if (!next || next.startsWith("--")) {
        setFlag(flags, key, true);
      } else {
        setFlag(flags, key, next);
        i++;
      }
      continue;
    }
    rest.push(value);
  }
  return { command, flags, rest };
}

function setFlag(flags: Record<string, string | boolean | string[]>, key: string, value: string | boolean): void {
  const current = flags[key];
  if (current === undefined) {
    flags[key] = value;
    return;
  }
  if (Array.isArray(current)) {
    current.push(String(value));
    return;
  }
  flags[key] = [String(current), String(value)];
}

function stringFlag(args: ParsedArgs, name: string): string | undefined {
  const value = args.flags[name];
  if (Array.isArray(value)) {
    return value[value.length - 1];
  }
  return typeof value === "string" ? value : undefined;
}

function stringFlags(args: ParsedArgs, name: string): string[] {
  const value = args.flags[name];
  if (Array.isArray(value)) {
    return value;
  }
  return typeof value === "string" ? [value] : [];
}

function providerFlag(args: ParsedArgs): "claude" | "codex" | undefined {
  const value = stringFlag(args, "provider")?.trim().toLowerCase();
  if (value === "claude" || value === "codex") {
    return value;
  }
  return undefined;
}

function parseExpParams(args: ParsedArgs): Record<string, unknown> {
  const paramsText = stringFlag(args, "params");
  const params = paramsText ? (JSON.parse(paramsText) as Record<string, unknown>) : {};
  for (const item of stringFlags(args, "set")) {
    const index = item.indexOf("=");
    if (index <= 0) {
      throw new Error(`invalid --set value, expected key=value: ${item}`);
    }
    params[item.slice(0, index)] = parseScalar(item.slice(index + 1));
  }
  return params;
}

function parseScalar(value: string): unknown {
  if (value === "true") return true;
  if (value === "false") return false;
  if (value !== "" && Number.isFinite(Number(value))) return Number(value);
  return value;
}

function splitList(value?: string): string[] {
  return value
    ? value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
    : [];
}

function usage(): void {
  console.error(`usage:
  npm run chat -- [--input dbus.json] [--message "..."] [--session <id>] [--json]
  npm run pipe                (stdin/stdout NDJSON IPC for desktop app)
  npm run mcp                 (stdio MCP server for Codex)
  npm run exp -- list [--json]
  npm run exp -- render --template <id> [--out /tmp/kubetrail-exp/run] [--set key=value] [--params '{"namespace":"default"}']
  npm run env
`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
