#!/usr/bin/env node

import { parseArgs } from "node:util";
import { resolve } from "node:path";
import {
  buildReport,
  createRun,
  formatRunSummary,
  getRunSummary,
  pickAutoTarget,
  preflight,
  resolveContractSource,
  searchReconTargets,
  verifyRun,
} from "./core.js";

const HELP = `hunt — Web3 Security Bug Hunter for Pi (Mainnet Focus & Fork Verification)

Usage:
  hunt [target]                   Start a hunt on a local repo or contract (default: .)
  hunt auto [query]               Autonomous mode: scout high-TVL mainnet target, pull verified code & start hunt
  hunt recon [query]              Search high-TVL mainnet protocols & Immunefi bug bounty targets
  hunt fetch <address> -c <chain> Download verified mainnet contract code & scaffold Foundry PoC
  hunt status [id]                Show current or specified hunt summary
  hunt report [id]                Generate markdown bounty report
  hunt verify [id]                Verify cryptographic evidence ledger
  hunt check                      Check scanner & fuzzing tools availability

Options:
  -c, --chain <id>        Chain ID for on-chain target (1: ETH, 42161: Arb, 8453: Base, 146: Sonic, etc.)
  -p, --program <name>    Bounty program name (default: target name)
  -m, --mode <mode>       Hunting mode: goal | list | loop (default: goal)
  -d, --dir <path>        Destination directory for fetched contracts (default: ./<contract-name>)
  --category <name>       Filter recon targets by category (lending, dex, yield, liquid-staking)
  --json                  JSON output

Examples:
  hunt auto                       # Auto-scout top TVL mainnet protocol (Aave, Uniswap, etc.) & initiate hunt
  hunt auto dex                   # Auto-scout top DEX protocol on Mainnet
  hunt auto base                  # Auto-scout top protocol on Base
  hunt recon aave                 # Scout Aave V3 mainnet contracts & Immunefi bounty scope
  hunt fetch 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 -c 1  # Pull Ethereum Aave V3 Pool
  hunt 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 -c 1 --program "Aave V3"
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
      dir: { type: "string", short: "d" },
      category: { type: "string" },
    },
  });

  const isJson = Boolean(parsed.values.json);
  const positionals = parsed.positionals;
  const firstArg = positionals[0];

  if (parsed.values.help || !firstArg || firstArg === "help" || firstArg === "--help" || firstArg === "-h") {
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

  // Subcommand: auto / loop
  if (firstArg === "auto" || firstArg === "loop") {
    const query = positionals.slice(1).join(" ") || (parsed.values.category as string | undefined);
    const chainId = parseInteger(parsed.values.chain as string | undefined);

    const selection = await pickAutoTarget(query, chainId);
    const targetDir = resolve(process.cwd(), (parsed.values.dir as string | undefined) ?? `${selection.target.id}-audit`);

    process.stdout.write(`Auto-scouting high-TVL target: ${selection.target.name} (${selection.target.category.toUpperCase()} | Max Bounty: $${selection.target.maxBountyUsd.toLocaleString()})\n`);
    process.stdout.write(`Target Contract: ${selection.primaryContract.name} (\`${selection.primaryContract.address}\`) on [Chain ${selection.primaryChainId}] ${selection.chainName}\n`);
    process.stdout.write(`Pulling verified sources and setting up Foundry fork workspace at ${targetDir}...\n`);

    const fetchResult = await resolveContractSource(selection.primaryContract.address, selection.primaryChainId, targetDir);

    const run = await createRun({
      cwd: process.cwd(),
      target: fetchResult.sourceFound ? targetDir : selection.primaryContract.address,
      program: selection.target.name,
      authorized: true,
      chainId: selection.primaryChainId,
      ...(process.env.WEB3_HUNTER_RPC_URL ? { rpcUrl: process.env.WEB3_HUNTER_RPC_URL } : {}),
    });

    output(
      isJson,
      "auto_started",
      { selection, fetchResult, run },
      `\n✓ Autonomous Web3 Hunt Initiated: ${run.id}\n` +
        `  Target: ${selection.target.name} (${selection.primaryContract.name})\n` +
        `  Bounty Scope: ${selection.target.bountyUrl}\n` +
        `  Workspace: ${targetDir}\n` +
        `  Foundry Fork Test: ${targetDir}/test/ExploitPoC.t.sol\n`,
    );
    return;
  }

  // Subcommand: recon / targets
  if (firstArg === "recon" || firstArg === "targets") {
    const query = positionals[1];
    const chainId = parseInteger(parsed.values.chain as string | undefined);
    const category = parsed.values.category as string | undefined;

    const targets = await searchReconTargets({ query, chainId, category });
    if (targets.length === 0) {
      output(isJson, "recon_targets", [], "No matching mainnet bounty targets found.");
      return;
    }

    const human = targets
      .map((t) => {
        const chainsStr = t.chains
          .map(
            (c) =>
              `  • [Chain ${c.chainId}] ${c.chainName}:\n` +
              c.contracts.map((k) => `      - ${k.name} (${k.role}): ${k.address}`).join("\n"),
          )
          .join("\n");

        return `[${t.name}] (${t.category.toUpperCase()} | Max Bounty: $${t.maxBountyUsd.toLocaleString()})\n` +
          `  Bounty: ${t.bountyUrl} (${t.bountyPlatform})\n` +
          `  Contracts:\n${chainsStr}`;
      })
      .join("\n\n");

    output(isJson, "recon_targets", targets, human);
    return;
  }

  // Subcommand: fetch
  if (firstArg === "fetch") {
    const address = positionals[1];
    const chainId = parseInteger(parsed.values.chain as string | undefined);
    if (!address || chainId === undefined) {
      throw new Error("Usage: hunt fetch <contract-address> -c <chainId> [-d <destination-dir>]");
    }

    const dest = resolve(process.cwd(), (parsed.values.dir as string | undefined) ?? address);
    const result = await resolveContractSource(address, chainId, dest);

    if (!result.sourceFound) {
      throw new Error(`Could not find verified source code for ${address} on Chain ID ${chainId}`);
    }

    output(
      isJson,
      "contract_fetched",
      result,
      `✓ Verified source fetched: ${result.contractName ?? address}\n` +
        `  Location: ${result.path}\n` +
        `  Files (${result.files.length}):\n` +
        result.files.map((f) => `    - ${f}`).join("\n") +
        `\n  Foundry PoC template generated at ${result.path}/test/ExploitPoC.t.sol`,
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
