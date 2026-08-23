#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import {
  buildReport,
  createRun,
  formatRunSummary,
  getRunSummary,
  OPERATIONS,
  preflight,
  recordFinding,
  runOperation,
  verifyRun,
  type FindingInput,
  type Operation,
  type OperationInput,
} from "./core.js";

const HELP = `pi-web3-hunter — deterministic Web3 hunt runner

Commands:
  preflight [--json]
  init <target> --program <name> --authorized [--chain-id N] [--json]
  status --run <run-id> [--json]
  run --run <run-id> --operation <name> --allow-host [selectors] [--json]
  finding --run <run-id> --input <finding.json> [--json]
  report --run <run-id> [--json]
  verify --run <run-id> [--json]

Operations: ${OPERATIONS.join(", ")}

Environment:
  WEB3_HUNTER_RPC_URL    RPC used by cast-code and fork tests; never written to evidence
  WEB3_HUNTER_STATE_DIR  Override the private state directory
`;

function output(json: boolean, type: string, value: unknown, human: string): void {
  process.stdout.write(json ? `${JSON.stringify({ type, value })}\n` : `${human}\n`);
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integer(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} must be an integer`);
  return parsed;
}

function commonOptions() {
  return { json: { type: "boolean" as const, default: false } };
}

async function main(argv: string[]): Promise<void> {
  const [command = "help", ...args] = argv;

  if (command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(HELP);
    return;
  }

  if (command === "preflight") {
    const parsed = parseArgs({ args, strict: true, options: commonOptions() });
    const result = await preflight();
    output(
      parsed.values.json,
      "preflight",
      result,
      result.map((item) => `${item.available ? "✓" : "✗"} ${item.name}${item.path ? `: ${item.path}` : ""}`).join("\n"),
    );
    return;
  }

  if (command === "init") {
    const parsed = parseArgs({
      args,
      allowPositionals: true,
      strict: true,
      options: {
        ...commonOptions(),
        program: { type: "string" },
        authorized: { type: "boolean", default: false },
        "chain-id": { type: "string" },
      },
    });
    if (parsed.positionals.length !== 1) throw new Error("init requires exactly one target");
    const chainId = integer(parsed.values["chain-id"], "chain-id");
    const run = await createRun({
      cwd: process.cwd(),
      target: parsed.positionals[0] ?? "",
      program: required(parsed.values.program, "program"),
      authorized: parsed.values.authorized,
      ...(chainId !== undefined ? { chainId } : {}),
      ...(process.env.WEB3_HUNTER_RPC_URL ? { rpcUrl: process.env.WEB3_HUNTER_RPC_URL } : {}),
    });
    output(parsed.values.json, "run_started", run, `Started ${run.id}\nTarget: ${run.scope.target}`);
    return;
  }

  if (command === "status") {
    const parsed = parseArgs({ args, strict: true, options: { ...commonOptions(), run: { type: "string" } } });
    const result = await getRunSummary(required(parsed.values.run, "run"));
    output(parsed.values.json, "run_status", result, formatRunSummary(result));
    return;
  }

  if (command === "run") {
    const parsed = parseArgs({
      args,
      strict: true,
      options: {
        ...commonOptions(),
        run: { type: "string" },
        operation: { type: "string" },
        "allow-host": { type: "boolean", default: false },
        "match-path": { type: "string" },
        "match-contract": { type: "string" },
        "match-test": { type: "string" },
        "contract-path": { type: "string" },
        "contract-name": { type: "string" },
        config: { type: "string" },
        "fork-block": { type: "string" },
        timeout: { type: "string" },
      },
    });
    const operation = required(parsed.values.operation, "operation") as Operation;
    if (!OPERATIONS.includes(operation)) throw new Error(`operation must be one of: ${OPERATIONS.join(", ")}`);
    const forkBlockNumber = integer(parsed.values["fork-block"], "fork-block");
    const timeoutMs = integer(parsed.values.timeout, "timeout");
    const input: OperationInput = {
      operation,
      ...(parsed.values["match-path"] !== undefined ? { matchPath: parsed.values["match-path"] } : {}),
      ...(parsed.values["match-contract"] !== undefined ? { matchContract: parsed.values["match-contract"] } : {}),
      ...(parsed.values["match-test"] !== undefined ? { matchTest: parsed.values["match-test"] } : {}),
      ...(parsed.values["contract-path"] !== undefined ? { contractPath: parsed.values["contract-path"] } : {}),
      ...(parsed.values["contract-name"] !== undefined ? { contractName: parsed.values["contract-name"] } : {}),
      ...(parsed.values.config !== undefined ? { configPath: parsed.values.config } : {}),
      ...(forkBlockNumber !== undefined ? { forkBlockNumber } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    };
    const controller = new AbortController();
    const abort = () => controller.abort();
    process.once("SIGINT", abort);
    try {
      const result = await runOperation(required(parsed.values.run, "run"), input, {
        allowHostExec: parsed.values["allow-host"],
        signal: controller.signal,
        ...(parsed.values.json
          ? {}
          : { onUpdate: (update: { text: string }) => process.stderr.write(update.text) }),
      });
      output(
        parsed.values.json,
        "tool_finished",
        result,
        `${result.command.join(" ")} exited ${result.exitCode}\n${result.artifacts.map((item) => item.path).join("\n")}`,
      );
    } finally {
      process.removeListener("SIGINT", abort);
    }
    return;
  }

  if (command === "finding") {
    const parsed = parseArgs({
      args,
      strict: true,
      options: { ...commonOptions(), run: { type: "string" }, input: { type: "string" } },
    });
    const input = JSON.parse(await readFile(required(parsed.values.input, "input"), "utf8")) as FindingInput;
    const result = await recordFinding(required(parsed.values.run, "run"), input);
    output(parsed.values.json, "finding_recorded", result, `${result.status}: ${result.id} ${result.title}`);
    return;
  }

  if (command === "report") {
    const parsed = parseArgs({ args, strict: true, options: { ...commonOptions(), run: { type: "string" } } });
    const path = await buildReport(required(parsed.values.run, "run"));
    output(parsed.values.json, "report_ready", { path }, `Report written: ${path}`);
    return;
  }

  if (command === "verify") {
    const parsed = parseArgs({ args, strict: true, options: { ...commonOptions(), run: { type: "string" } } });
    const result = await verifyRun(required(parsed.values.run, "run"));
    output(
      parsed.values.json,
      "evidence_verified",
      result,
      `Evidence valid: ${result.eventCount} events, ${result.artifactCount} artifacts, ${result.lastEventHash}`,
    );
    return;
  }

  throw new Error(`Unknown command: ${command}\n\n${HELP}`);
}

main(process.argv.slice(2)).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  const json = process.argv.includes("--json");
  const value = error && typeof error === "object" && "code" in error ? { code: String(error.code), message } : { message };
  process.stderr.write(json ? `${JSON.stringify({ type: "error", value })}\n` : `Error: ${message}\n`);
  process.exitCode = 1;
});
