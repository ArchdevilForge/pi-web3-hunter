#!/usr/bin/env node

import { parseArgs } from "node:util";
import {
  buildReport,
  createRun,
  formatRunSummary,
  getRunSummary,
  preflight,
  verifyRun,
} from "./core.js";

const HELP = `hunt — Web3 Security Bug Hunter for Pi

Usage:
  hunt [target]           Start a hunt on a local repo or contract (default: .)
  hunt status [id]        Show current or specified hunt summary
  hunt report [id]        Generate markdown bounty report
  hunt verify [id]        Verify cryptographic evidence ledger
  hunt check              Check scanner tools availability

Options:
  -c, --chain <id>        Chain ID for on-chain target (e.g. 1, 42161, 8453)
  -p, --program <name>    Bounty program name (default: target name)
  -m, --mode <mode>       Hunting mode: goal | list | loop (default: goal)
  --json                  JSON output
`;

function output(json: boolean, type: string, value: unknown, human: string): void {
  process.stdout.write(json ? `${JSON.stringify({ type, value })}\n` : `${human}\n`);
}

function parseInteger(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const num = Number(value);
  if (!Number.isSafeInteger(num)) throw new Error(`Invalid number: ${value}`);
  return num;
}

async function main(argv: string[]): Promise<void> {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: {
      help: { type: "boolean", short: "h", default: false },
      json: { type: "boolean", default: false },
      chain: { type: "string", short: "c" },
      program: { type: "string", short: "p" },
      mode: { type: "string", short: "m", default: "goal" },
    },
  });

  const isJson = Boolean(parsed.values.json);
  const positionals = parsed.positionals;
  const firstArg = positionals[0];

  if (parsed.values.help || firstArg === "help" || firstArg === "--help" || firstArg === "-h") {
    process.stdout.write(HELP);
    return;
  }

  // Subcommand: check / preflight
  if (firstArg === "check" || firstArg === "preflight") {
    const result = await preflight();
    output(
      isJson,
      "preflight",
      result,
      result.map((item) => `${item.available ? "✓" : "✗"} ${item.name}${item.path ? `: ${item.path}` : ""}`).join("\n"),
    );
    return;
  }

  // Subcommand: status
  if (firstArg === "status") {
    const runId = positionals[1];
    if (!runId) throw new Error("Usage: pi-web3-hunter status <run-id>");
    const result = await getRunSummary(runId);
    output(isJson, "status", result, formatRunSummary(result));
    return;
  }

  // Subcommand: report
  if (firstArg === "report") {
    const runId = positionals[1];
    if (!runId) throw new Error("Usage: pi-web3-hunter report <run-id>");
    const path = await buildReport(runId);
    output(isJson, "report", { path }, `Report written: ${path}`);
    return;
  }

  // Subcommand: verify
  if (firstArg === "verify") {
    const runId = positionals[1];
    if (!runId) throw new Error("Usage: pi-web3-hunter verify <run-id>");
    const result = await verifyRun(runId);
    output(
      isJson,
      "verify",
      result,
      `Evidence valid: ${result.eventCount} events, ${result.artifactCount} artifacts, last hash ${result.lastEventHash}`,
    );
    return;
  }

  // Default: Start hunt on target (defaults to ".")
  const target = firstArg ?? ".";
  const chainId = parseInteger(parsed.values.chain as string | undefined);
  const programName = (parsed.values.program as string | undefined) ?? (target === "." ? "Local Workspace" : target);

  const run = await createRun({
    cwd: process.cwd(),
    target,
    program: programName,
    authorized: true,
    ...(chainId !== undefined ? { chainId } : {}),
    ...(process.env.WEB3_HUNTER_RPC_URL ? { rpcUrl: process.env.WEB3_HUNTER_RPC_URL } : {}),
  });

  output(isJson, "run_started", run, `Started Web3 Hunt (${parsed.values.mode}): ${run.id}\nTarget: ${run.scope.target}`);
}

main(process.argv.slice(2)).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  const json = process.argv.includes("--json");
  const value = error && typeof error === "object" && "code" in error ? { code: String(error.code), message } : { message };
  process.stderr.write(json ? `${JSON.stringify({ type: "error", value })}\n` : `Error: ${message}\n`);
  process.exitCode = 1;
});
