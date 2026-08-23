import { parseArgs } from "node:util";
import { Type } from "typebox";
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
  type RunSummary,
  type Severity,
} from "./core.js";
import {
  isToolCallEventType,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { generatePoCTemplate, PoCService, PoCServiceLive } from "./services/PoCService.js";
import { DetachedAuditorService, DetachedAuditorServiceLive } from "./services/DetachedAuditorService.js";
import { ScannerServiceLive } from "./services/ScannerService.js";
import { Effect, Layer } from "effect";

const SESSION_ENTRY = "pi-web3-hunter:active-run";
const TOOL_GUIDELINES = [
  "Use Web3 Hunter tools for scanner execution and evidence handling during an active hunt.",
  "Keep testing inside the attested bounty scope and reproduce impact on local forks or test environments.",
  "Record a confirmed finding only after all seven validation gates pass with captured evidence.",
  "Use web3_scaffold_poc to create verifiable Foundry PoC exploit contracts.",
  "Use web3_detached_audit to independently verify findings via clean detached subprocess.",
];

const OperationSchema = Type.Union(OPERATIONS.map((operation) => Type.Literal(operation)));
const SeveritySchema = Type.Union(
  (["critical", "high", "medium", "low", "informational"] as const).map((severity) => Type.Literal(severity)),
);
const FindingStatusSchema = Type.Union(
  (["candidate", "confirmed", "killed"] as const).map((status) => Type.Literal(status)),
);
const GatesSchema = Type.Object({
  reproduced: Type.Boolean({ description: "Exploit or invariant violation reproduced" }),
  impactInScope: Type.Boolean({ description: "Impact is accepted by the bounty program" }),
  rootCauseInScope: Type.Boolean({ description: "Root cause is in an in-scope asset" }),
  realisticAttacker: Type.Boolean({ description: "Attacker permissions and capital are realistic" }),
  notKnownOrIntended: Type.Boolean({ description: "Behavior is not documented, accepted, or already known" }),
  impactDemonstrated: Type.Boolean({ description: "Concrete impact is demonstrated, not hypothetical" }),
  pinnedAndRepeatable: Type.Boolean({ description: "Commit, chain, block, and reproduction are pinned and repeatable" }),
});

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (const character of input) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = undefined;
      else current += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (/\s/u.test(character)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += character;
  }
  if (escaped || quote) throw new Error("Unclosed quote or escape in command arguments");
  if (current) tokens.push(current);
  return tokens;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function reconstructRun(ctx: ExtensionContext): string | undefined {
  let runId: string | undefined;
  for (const entry of ctx.sessionManager.getBranch()) {
    if (entry.type !== "custom" || entry.customType !== SESSION_ENTRY) continue;
    const data = entry.data as { runId?: unknown } | undefined;
    if (typeof data?.runId === "string") runId = data.runId;
  }
  return runId;
}

async function updateWidget(ctx: ExtensionContext, runId: string | undefined): Promise<RunSummary | undefined> {
  if (!runId) {
    ctx.ui.setStatus("web3-hunter", undefined);
    ctx.ui.setWidget("web3-hunter", undefined);
    return undefined;
  }
  const summary = await getRunSummary(runId);
  ctx.ui.setStatus("web3-hunter", `web3:${summary.run.state.toLowerCase()} ${summary.findings.confirmed}✓`);
  ctx.ui.setWidget("web3-hunter", [
    `Web3 Hunt ${summary.run.id}`,
    `${summary.run.state} · ${summary.run.scope.program}`,
    `${summary.findings.confirmed} confirmed · ${summary.findings.candidate} candidate · ${summary.findings.killed} killed`,
  ]);
  return summary;
}

function currentOrRequested(currentRunId: string | undefined, requested?: string): string {
  const runId = requested ?? currentRunId;
  if (!runId) throw new Error("No active Web3 hunt. Start one with /hunt.");
  return runId;
}

export default function web3Hunter(pi: ExtensionAPI) {
  let currentRunId: string | undefined;

  pi.registerFlag("web3-host-exec", {
    description: "Allow Web3 Hunter to execute allowlisted host scanners; use only inside an isolated environment",
    type: "boolean",
    default: false,
  });

  pi.on("session_start", async (_event, ctx) => {
    currentRunId = reconstructRun(ctx);
    try {
      await updateWidget(ctx, currentRunId);
    } catch (error) {
      ctx.ui.notify(`Web3 Hunter state error: ${errorMessage(error)}`, "warning");
    }
  });

  pi.on("session_tree", async (_event, ctx) => {
    currentRunId = reconstructRun(ctx);
    await updateWidget(ctx, currentRunId);
  });

  pi.on("before_agent_start", async (_event, _ctx) => {
    if (!currentRunId) return undefined;
    return {
      systemPrompt: [
        "An authorized Web3 Hunter run is active.",
        ...TOOL_GUIDELINES,
        "Host scanner commands must go through web3_run_tool; direct chain writes are outside this workflow.",
      ].join("\n"),
    };
  });

  pi.on("tool_call", async (event) => {
    if (!currentRunId || !isToolCallEventType("bash", event)) return undefined;
    const command = event.input.command;
    const chainWrite = /\bcast\s+send\b|\bforge\s+script\b[^\n]*--broadcast|--private-key\b|\bmnemonic\b/iu.test(command);
    if (!chainWrite) return undefined;
    return {
      block: true,
      reason: "Web3 Hunter blocks direct chain writes and private-key commands. Reproduce with local fork tests via web3_run_tool.",
    };
  });

  const handleHuntCommand = async (rawArgs: string, ctx: ExtensionContext) => {
    try {
      const tokens = tokenize(rawArgs);
      const firstToken = tokens[0];

      // Quick subcommands: status, report, verify, check
      if (firstToken === "status") {
        const runId = currentOrRequested(currentRunId, tokens[1]);
        const summary = await updateWidget(ctx, runId);
        if (summary) ctx.ui.notify(formatRunSummary(summary), "info");
        return;
      }

      if (firstToken === "report") {
        const runId = currentOrRequested(currentRunId, tokens[1]);
        const path = await buildReport(runId);
        await updateWidget(ctx, runId);
        ctx.ui.notify(`Report written: ${path}`, "info");
        return;
      }

      if (firstToken === "verify") {
        const runId = currentOrRequested(currentRunId, tokens[1]);
        const result = await verifyRun(runId);
        ctx.ui.notify(`Evidence valid: ${result.eventCount} events, ${result.artifactCount} artifacts`, "info");
        return;
      }

      if (firstToken === "check" || firstToken === "preflight") {
        const caps = await preflight();
        ctx.ui.notify(caps.map((c) => `${c.available ? "✓" : "✗"} ${c.name}`).join("\n"), "info");
        return;
      }

      // Starting a hunt
      const parsed = parseArgs({
        args: tokens,
        allowPositionals: true,
        strict: false,
        options: {
          chain: { type: "string", short: "c" },
          "chain-id": { type: "string" },
          program: { type: "string", short: "p" },
          mode: { type: "string", short: "m", default: "goal" },
          authorized: { type: "boolean", default: true },
        },
      });

      const target = parsed.positionals[0] ?? ".";
      const chainRaw = (parsed.values.chain as string | undefined) ?? (parsed.values["chain-id"] as string | undefined);
      const chainId = chainRaw !== undefined ? Number(chainRaw) : undefined;
      const programName = (parsed.values.program as string | undefined) ?? (target === "." ? "Local Workspace" : target);
      const mode = (parsed.values.mode as string | undefined) ?? "goal";

      const run = await createRun({
        cwd: ctx.cwd,
        target,
        program: programName,
        authorized: true,
        ...(chainId !== undefined ? { chainId } : {}),
        ...(process.env.WEB3_HUNTER_RPC_URL ? { rpcUrl: process.env.WEB3_HUNTER_RPC_URL } : {}),
      });

      currentRunId = run.id;
      pi.appendEntry(SESSION_ENTRY, { runId: run.id });
      ctx.ui.notify(`Web3 hunt (${mode}) started: ${run.id}`, "info");
      await updateWidget(ctx, run.id);
      pi.sendUserMessage(`/skill:web3-hunt run-id=${run.id} mode=${mode} target=${run.scope.target}`, {
        ...(ctx.isIdle() ? {} : { deliverAs: "followUp" as const }),
        expandPromptTemplates: true,
      });
    } catch (error) {
      ctx.ui.notify(errorMessage(error), "error");
      throw error;
    }
  };

  // Primary concise command: /hunt
  pi.registerCommand("hunt", {
    description: "KISS Web3 Hunt: /hunt [target|status|report|verify|check] [-c <chain>] [-m <goal|list|loop>]",
    handler: handleHuntCommand,
  });

  // Alias: /hunt-web3
  pi.registerCommand("hunt-web3", {
    description: "Alias for /hunt",
    handler: handleHuntCommand,
  });

  pi.registerTool({
    name: "web3_preflight",
    label: "Web3 Preflight",
    description: "Check whether supported Web3 analysis tools (forge, slither, aderyn, halmos, echidna, medusa, anvil, cast, docker) are available.",
    promptSnippet: "Check local Web3 scanner availability",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({}),
    executionMode: "parallel",
    async execute() {
      const capabilities = await preflight();
      return {
        content: [{ type: "text", text: capabilities.map((item) => `${item.available ? "✓" : "✗"} ${item.name}${item.path ? `: ${item.path}` : ""}`).join("\n") }],
        details: { capabilities },
      };
    },
  });

  pi.registerTool({
    name: "web3_hunt_status",
    label: "Web3 Hunt Status",
    description: "Read the active hunt scope, state, finding counts, and evidence directory.",
    promptSnippet: "Inspect an authorized Web3 hunt run",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({ runId: Type.Optional(Type.String()) }),
    executionMode: "sequential",
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const summary = await updateWidget(ctx, runId);
      if (!summary) throw new Error("Run not found");
      return { content: [{ type: "text", text: formatRunSummary(summary) }], details: summary };
    },
  });

  pi.registerTool({
    name: "web3_run_tool",
    label: "Web3 Tool",
    description: "Execute one allowlisted read-only Web3 scanner operation (forge-build, forge-test, slither, aderyn, halmos, echidna, medusa, cast-code) and capture stdout/stderr as hashed evidence.",
    promptSnippet: "Run an allowlisted Web3 scanner with evidence capture",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({
      runId: Type.Optional(Type.String()),
      operation: OperationSchema,
      matchPath: Type.Optional(Type.String()),
      matchContract: Type.Optional(Type.String()),
      matchTest: Type.Optional(Type.String()),
      contractPath: Type.Optional(Type.String()),
      contractName: Type.Optional(Type.String()),
      configPath: Type.Optional(Type.String()),
      forkBlockNumber: Type.Optional(Type.Integer({ minimum: 0 })),
      timeoutMs: Type.Optional(Type.Integer({ minimum: 1_000, maximum: 900_000 })),
    }),
    executionMode: "sequential",
    async execute(_id, params, signal, onUpdate, ctx) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const input: OperationInput = {
        operation: params.operation as Operation,
        ...(params.matchPath !== undefined ? { matchPath: params.matchPath } : {}),
        ...(params.matchContract !== undefined ? { matchContract: params.matchContract } : {}),
        ...(params.matchTest !== undefined ? { matchTest: params.matchTest } : {}),
        ...(params.contractPath !== undefined ? { contractPath: params.contractPath } : {}),
        ...(params.contractName !== undefined ? { contractName: params.contractName } : {}),
        ...(params.configPath !== undefined ? { configPath: params.configPath } : {}),
        ...(params.forkBlockNumber !== undefined ? { forkBlockNumber: params.forkBlockNumber } : {}),
        ...(params.timeoutMs !== undefined ? { timeoutMs: params.timeoutMs } : {}),
      };
      const result = await runOperation(runId, input, {
        allowHostExec: pi.getFlag("web3-host-exec") === true,
        ...(signal ? { signal } : {}),
        ...(onUpdate
          ? {
              onUpdate: (update) => onUpdate({
                content: [{ type: "text", text: `${update.stream}: ${update.text}` }],
                details: { operation: input.operation, update },
              }),
            }
          : {}),
      });
      await updateWidget(ctx, runId);
      const text = [
        `${result.command.join(" ")} exited ${result.exitCode} in ${result.durationMs}ms`,
        ...result.artifacts.map((artifact) => `${artifact.path} sha256:${artifact.sha256}`),
      ].join("\n");
      return { content: [{ type: "text", text }], details: result };
    },
  });

  pi.registerTool({
    name: "web3_scaffold_poc",
    label: "Scaffold Foundry PoC",
    description: "Generate a standard Foundry exploit test contract template in test/exploit/PoC_<findingId>.t.sol with balance & state delta assertions.",
    promptSnippet: "Create a reproducible Foundry exploit test contract",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({
      runId: Type.Optional(Type.String()),
      findingId: Type.String({ description: "Unique finding identifier (e.g. finding-01)" }),
      targetContract: Type.String({ description: "Target contract address or name" }),
      chainId: Type.Optional(Type.Integer({ default: 1 })),
      forkBlock: Type.Optional(Type.Integer()),
      setupLogic: Type.Optional(Type.String()),
      exploitLogic: Type.Optional(Type.String()),
    }),
    executionMode: "sequential",
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const summary = await getRunSummary(runId);
      const template = generatePoCTemplate({
        findingTitle: params.findingId,
        targetContract: params.targetContract,
        chainId: params.chainId ?? 1,
        ...(params.forkBlock !== undefined ? { forkBlock: params.forkBlock } : {}),
        ...(params.setupLogic !== undefined ? { setupLogic: params.setupLogic } : {}),
        ...(params.exploitLogic !== undefined ? { exploitLogic: params.exploitLogic } : {}),
      });
      const scaffoldEffect = Effect.gen(function* () {
        const poc = yield* PoCService;
        return yield* poc.scaffoldPoC(summary.run.scope.targetRoot, params.findingId, template);
      }).pipe(Effect.provide(PoCServiceLive));
      const filePath = await Effect.runPromise(scaffoldEffect);
      return {
        content: [{ type: "text", text: `PoC scaffolded at: ${filePath}` }],
        details: { filePath, template },
      };
    },
  });

  pi.registerTool({
    name: "web3_detached_audit",
    label: "Detached Audit Verification",
    description: "Execute a detached, isolated 7-gate audit check on a candidate finding to verify PoC pass and non-falsifiability before recording.",
    promptSnippet: "Run isolated 7-gate detached audit check",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({
      runId: Type.Optional(Type.String()),
      title: Type.String(),
      severity: SeveritySchema,
      status: FindingStatusSchema,
      rootCause: Type.String(),
      impact: Type.String(),
      reproduction: Type.String(),
      gates: GatesSchema,
      evidencePaths: Type.Array(Type.String(), { maxItems: 32 }),
    }),
    executionMode: "sequential",
    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const summary = await getRunSummary(runId);
      const auditLayer = DetachedAuditorServiceLive.pipe(
        Layer.provide(ScannerServiceLive),
        Layer.provide(PoCServiceLive),
      );
      const auditEffect = Effect.provide(
        DetachedAuditorService.pipe(
          Effect.flatMap((auditor) =>
            auditor.auditFinding(summary.run, {
              title: params.title,
              severity: params.severity as Severity,
              status: params.status,
              rootCause: params.rootCause,
              impact: params.impact,
              reproduction: params.reproduction,
              gates: params.gates,
              evidencePaths: params.evidencePaths,
            }),
          ),
        ),
        auditLayer,
      );
      const result = await Effect.runPromise(auditEffect);
      return {
        content: [{ type: "text", text: `Detached Audit Result: ${result.approved ? "APPROVED ✓" : "REJECTED ✗"}\n${result.executionLog}${result.reason ? `\nReason: ${result.reason}` : ""}` }],
        details: result,
      };
    },
  });

  pi.registerTool({
    name: "web3_record_finding",
    label: "Record Web3 Finding",
    description: "Record a candidate, confirmed, or killed finding. Confirmed findings require all seven gates and evidence files.",
    promptSnippet: "Store a validation-gated Web3 finding",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({
      runId: Type.Optional(Type.String()),
      title: Type.String(),
      severity: SeveritySchema,
      status: FindingStatusSchema,
      rootCause: Type.String(),
      impact: Type.String(),
      reproduction: Type.String(),
      gates: GatesSchema,
      evidencePaths: Type.Array(Type.String(), { maxItems: 32 }),
    }),
    executionMode: "sequential",
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const input: FindingInput = {
        title: params.title,
        severity: params.severity as Severity,
        status: params.status,
        rootCause: params.rootCause,
        impact: params.impact,
        reproduction: params.reproduction,
        gates: params.gates,
        evidencePaths: params.evidencePaths,
      };
      const finding = await recordFinding(runId, input);
      await updateWidget(ctx, runId);
      return {
        content: [{ type: "text", text: `${finding.status}: ${finding.id} ${finding.title}` }],
        details: finding,
      };
    },
  });

  pi.registerTool({
    name: "web3_build_report",
    label: "Build Web3 Report",
    description: "Build a Markdown report containing only findings that passed every validation gate.",
    promptSnippet: "Build an evidence-backed Web3 bounty report",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({ runId: Type.Optional(Type.String()) }),
    executionMode: "sequential",
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const path = await buildReport(runId);
      await updateWidget(ctx, runId);
      return { content: [{ type: "text", text: `Report written: ${path}` }], details: { runId, path } };
    },
  });

  pi.registerTool({
    name: "web3_verify_evidence",
    label: "Verify Web3 Evidence",
    description: "Verify the run's hash-chained ledger and every captured artifact digest.",
    promptSnippet: "Verify Web3 hunt evidence integrity",
    promptGuidelines: TOOL_GUIDELINES,
    parameters: Type.Object({ runId: Type.Optional(Type.String()) }),
    executionMode: "sequential",
    async execute(_id, params) {
      const runId = currentOrRequested(currentRunId, params.runId);
      const result = await verifyRun(runId);
      return {
        content: [{ type: "text", text: `Evidence valid: ${result.eventCount} events, ${result.artifactCount} artifacts, last hash ${result.lastEventHash}` }],
        details: result,
      };
    },
  });
}

export { tokenize };
