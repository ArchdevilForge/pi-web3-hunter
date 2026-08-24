import { Effect, Layer } from "effect";
import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";

import { HuntError, toHuntError } from "./errors.js";
import {
  Artifact,
  FindingInput,
  FindingRecord,
  FindingStatus,
  GATE_KEYS,
  HuntEvent,
  HuntRun,
  OPERATIONS,
  Operation,
  OperationInput,
  OperationResult,
  RUN_STATES,
  RunId,
  RunState,
  ScopeManifest,
  Severity,
  ToolCapability,
  ValidationGates,
} from "./schema.js";

import {
  assertRunId,
  atomicWrite,
  hashEvent,
  LedgerService,
  LedgerServiceLive,
  readJson,
  runDirectory,
  sha256,
  stateRoot,
  verifyEventChain,
  withRunLock,
} from "./services/LedgerService.js";
import {
  KNOWN_CHAINS,
  MultiChainService,
  MultiChainServiceLive,
} from "./services/MultiChainService.js";
import { ForkService, ForkServiceLive } from "./services/ForkService.js";
import {
  buildCommand,
  findExecutable,
  ScannerService,
  ScannerServiceLive,
} from "./services/ScannerService.js";
import { PoCService, PoCServiceLive } from "./services/PoCService.js";
import {
  DetachedAuditorService,
  DetachedAuditorServiceLive,
} from "./services/DetachedAuditorService.js";
import {
  AutoTargetSelection,
  CURATED_MAINNET_TARGETS,
  ProtocolTarget,
  ReconQueryOptions,
  ReconService,
  ReconServiceLive,
} from "./services/ReconService.js";

export {
  Artifact,
  AutoTargetSelection,
  CURATED_MAINNET_TARGETS,
  FindingInput,
  FindingRecord,
  FindingStatus,
  GATE_KEYS,
  HuntError,
  HuntEvent,
  HuntRun,
  KNOWN_CHAINS,
  ProtocolTarget,
  ReconQueryOptions,
  ReconService,
  ReconServiceLive,
  OPERATIONS,
  Operation,
  OperationInput,
  OperationResult,
  RUN_STATES,
  RunId,
  RunState,
  ScopeManifest,
  Severity,
  ToolCapability,
  ValidationGates,
};

const MAX_EVIDENCE_BYTES = 10 * 1024 * 1024;
const FINDING_ID_PATTERN = /^finding-[a-f0-9]{12}$/;
const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;

export interface ScopeInput {
  cwd: string;
  target: string;
  program: string;
  authorized: boolean;
  chainId?: number | undefined;
  rpcUrl?: string | undefined;
}

export interface OperationUpdate {
  stream: "stdout" | "stderr";
  text: string;
}

export interface RunSummary {
  run: HuntRun;
  runDirectory: string;
  findings: {
    candidate: number;
    confirmed: number;
    killed: number;
  };
}

export interface VerificationResult {
  valid: true;
  eventCount: number;
  artifactCount: number;
  lastEventHash: string;
}

// Combined Service Layer
export const AppLayerLive = Layer.mergeAll(
  LedgerServiceLive,
  MultiChainServiceLive,
  ForkServiceLive,
  ScannerServiceLive,
  PoCServiceLive,
).pipe(
  Layer.provideMerge(
    DetachedAuditorServiceLive.pipe(
      Layer.provide(ScannerServiceLive),
      Layer.provide(PoCServiceLive),
    ),
  ),
);

export function getStateRoot(): string {
  return stateRoot();
}

function cleanText(value: string, label: string, maxLength = 8_000): string {
  const cleaned = value.trim();
  if (!cleaned) throw new HuntError("INVALID_INPUT", `${label} is required`);
  if (cleaned.length > maxLength) throw new HuntError("INVALID_INPUT", `${label} exceeds ${maxLength} characters`);
  if (/\0|[\u0001-\u0008\u000b\u000c\u000e-\u001f]/u.test(cleaned)) {
    throw new HuntError("INVALID_INPUT", `${label} contains control characters`);
  }
  return cleaned;
}

function singleLineText(value: string, label: string, maxLength: number): string {
  const cleaned = cleanText(value, label, maxLength);
  if (/\r|\n/u.test(cleaned)) throw new HuntError("INVALID_INPUT", `${label} must be a single line`);
  return cleaned;
}

function isWithin(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value === "" || (!value.startsWith(`..${sep}`) && value !== ".." && !isAbsolute(value));
}

function normalizedRpcHost(rpcUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rpcUrl);
  } catch (cause) {
    throw new HuntError("INVALID_RPC_URL", "WEB3_HUNTER_RPC_URL is not a valid URL", { cause });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new HuntError("INVALID_RPC_URL", "WEB3_HUNTER_RPC_URL must use http: or https:");
  }
  return parsed.host;
}

async function resolveScope(input: ScopeInput): Promise<ScopeManifest> {
  if (!input.authorized) {
    throw new HuntError("AUTHORIZATION_REQUIRED", "Explicit authorization is required before a hunt can start");
  }
  const program = singleLineText(input.program, "program", 300);
  const workspace = await realpath(resolve(input.cwd));
  const createdAt = new Date().toISOString();

  const URL_PATTERN = /^https?:\/\//i;
  if (URL_PATTERN.test(input.target)) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(input.target);
    } catch (cause) {
      throw new HuntError("INVALID_TARGET", `Target URL "${input.target}" is not valid`, { cause });
    }
    const programName = input.program && input.program !== "Local Workspace"
      ? singleLineText(input.program, "program", 300)
      : parsedUrl.hostname;
    return {
      kind: "url",
      target: input.target.trim(),
      targetRoot: workspace,
      program: programName,
      authorization: "user-attested",
      ...(input.chainId ? { chainId: input.chainId } : {}),
      ...(input.rpcUrl ? { rpcHost: normalizedRpcHost(input.rpcUrl) } : {}),
      createdAt,
    };
  }

  if (ADDRESS_PATTERN.test(input.target)) {
    const chainId = input.chainId;
    if (!Number.isSafeInteger(chainId) || (chainId ?? 0) <= 0) {
      throw new HuntError("INVALID_CHAIN", "A positive chain id is required for a contract target");
    }
    return {
      kind: "contract",
      target: input.target.toLowerCase(),
      targetRoot: workspace,
      program,
      authorization: "user-attested",
      chainId: chainId as number,
      ...(input.rpcUrl ? { rpcHost: normalizedRpcHost(input.rpcUrl) } : {}),
      createdAt,
    };
  }

  let candidate: string;
  try {
    candidate = await realpath(resolve(workspace, input.target));
  } catch {
    throw new HuntError(
      "INVALID_TARGET",
      `Target "${input.target}" does not exist on disk. Run "/hunt" without arguments to hunt the current workspace, or pass an on-chain contract address (0x...).`,
    );
  }
  if (!isWithin(workspace, candidate)) {
    throw new HuntError("OUTSIDE_WORKSPACE", "Repository target must stay inside Pi's current workspace");
  }
  if (!(await stat(candidate)).isDirectory()) throw new HuntError("INVALID_TARGET", "Repository target must be a directory");
  return {
    kind: "repository",
    target: candidate,
    targetRoot: candidate,
    program,
    authorization: "user-attested",
    ...(input.chainId ? { chainId: input.chainId } : {}),
    ...(input.rpcUrl ? { rpcHost: normalizedRpcHost(input.rpcUrl) } : {}),
    createdAt,
  };
}

function newRunId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z").toLowerCase();
  return `run-${stamp}-${randomUUID().replaceAll("-", "").slice(0, 8)}`;
}

async function readEvents(directory: string): Promise<HuntEvent[]> {
  let content: string;
  try {
    content = await readFile(join(directory, "events.jsonl"), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const lines = content.split("\n").filter(Boolean);
  return lines.map((line, index) => {
    try {
      return JSON.parse(line) as HuntEvent;
    } catch (cause) {
      throw new HuntError("CORRUPT_LEDGER", `Invalid event JSON at line ${index + 1}`, { cause });
    }
  });
}

async function readRunUnsafe(runId: string): Promise<{ run: HuntRun; directory: string; events: HuntEvent[] }> {
  assertRunId(runId);
  const directory = runDirectory(runId);
  const rawRun = await readJson<HuntRun>(join(directory, "run.json"));
  if (rawRun.id !== runId || rawRun.version !== 1) throw new HuntError("CORRUPT_RUN", "Run metadata does not match the requested id");
  const events = await readEvents(directory);
  verifyEventChain(events);
  const last = events.at(-1);
  const run: HuntRun = last
    ? {
        ...rawRun,
        state: last.state,
        updatedAt: last.timestamp,
        eventCount: events.length,
        lastEventHash: last.hash,
      }
    : rawRun;
  return { run, directory, events };
}

async function appendEventUnsafe(
  runId: string,
  type: string,
  state: RunState,
  data: Record<string, unknown>,
): Promise<HuntEvent> {
  const directory = runDirectory(runId);
  return withRunLock(directory, async () => {
    const { run, events } = await readRunUnsafe(runId);
    const last = events.at(-1);
    const unsigned = {
      sequence: events.length + 1,
      timestamp: new Date().toISOString(),
      type,
      state,
      data,
      previousHash: last ? last.hash : "GENESIS",
    };
    const event: HuntEvent = {
      ...unsigned,
      hash: hashEvent(unsigned),
    };

    const updatedRun: HuntRun = {
      ...run,
      state,
      updatedAt: event.timestamp,
      eventCount: event.sequence,
      lastEventHash: event.hash,
    };

    await atomicWrite(join(directory, "run.json"), `${JSON.stringify(updatedRun, null, 2)}\n`);
    await writeFile(join(directory, "events.jsonl"), `${JSON.stringify(event)}\n`, { flag: "a", mode: 0o600 });
    return event;
  });
}

export async function runHuntEffect<T>(effect: Effect.Effect<T, HuntError>): Promise<T> {
  const result = await Effect.runPromise(Effect.either(effect));
  if (result._tag === "Left") throw result.left;
  return result.right;
}

export function createRunEffect(input: ScopeInput): Effect.Effect<HuntRun, HuntError> {
  return Effect.gen(function* () {
    const scope = yield* Effect.tryPromise({
      try: () => resolveScope(input),
      catch: (cause) => toHuntError("SCOPE_ERROR", cause),
    });
    const now = new Date().toISOString();
    const run: HuntRun = {
      version: 1,
      id: newRunId(),
      state: "SCOPED",
      scope,
      createdAt: now,
      updatedAt: now,
      eventCount: 0,
      lastEventHash: "GENESIS",
    };
    const directory = runDirectory(run.id);
    yield* Effect.tryPromise({
      try: async () => {
        await mkdir(join(directory, "artifacts"), { recursive: true, mode: 0o700 });
        await mkdir(join(directory, "findings"), { recursive: true, mode: 0o700 });
        await atomicWrite(join(directory, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
        await appendEventUnsafe(run.id, "scope_verified", "SCOPED", {
          kind: scope.kind,
          target: scope.target,
          program: scope.program,
          ...(scope.chainId ? { chainId: scope.chainId } : {}),
          ...(scope.rpcHost ? { rpcHost: scope.rpcHost } : {}),
        });
      },
      catch: (cause) => toHuntError("STATE_WRITE_FAILED", cause),
    });
    const loaded = yield* Effect.tryPromise({
      try: async () => (await readRunUnsafe(run.id)).run,
      catch: (cause) => toHuntError("STATE_READ_FAILED", cause),
    });
    return loaded;
  });
}

export async function createRun(input: ScopeInput): Promise<HuntRun> {
  return runHuntEffect(createRunEffect(input));
}

export function preflightEffect(): Effect.Effect<ToolCapability[], HuntError> {
  const tools = ["forge", "anvil", "cast", "slither", "aderyn", "halmos", "echidna", "medusa", "docker"] as const;
  return Effect.forEach(
    tools,
    (name) =>
      Effect.tryPromise({
        try: async () => {
          const path = await findExecutable(name);
          return { name, available: Boolean(path), ...(path ? { path } : {}) };
        },
        catch: (cause) => toHuntError("PREFLIGHT_FAILED", cause),
      }),
    { concurrency: 4 },
  );
}

export async function preflight(): Promise<ToolCapability[]> {
  return runHuntEffect(preflightEffect());
}

async function writeOperationArtifacts(
  runId: string,
  operation: Operation,
  result: { stdout: string; stderr: string },
): Promise<Artifact[]> {
  const directory = runDirectory(runId);
  const artifacts: Artifact[] = [];
  const baseName = `${Date.now()}-${operation}`;
  if (result.stdout.length) {
    const path = join(directory, "artifacts", `${baseName}.stdout.log`);
    const data = Buffer.from(result.stdout, "utf8");
    await atomicWrite(path, data);
    artifacts.push({ path, sha256: sha256(data), size: data.length });
  }
  if (result.stderr.length) {
    const path = join(directory, "artifacts", `${baseName}.stderr.log`);
    const data = Buffer.from(result.stderr, "utf8");
    await atomicWrite(path, data);
    artifacts.push({ path, sha256: sha256(data), size: data.length });
  }
  return artifacts;
}

export function runOperationEffect(
  runId: string,
  input: OperationInput,
  options: { allowHostExec: boolean; signal?: AbortSignal | undefined; onUpdate?: ((update: OperationUpdate) => void) | undefined },
): Effect.Effect<OperationResult, HuntError> {
  return Effect.gen(function* () {
    if (!options.allowHostExec) {
      return yield* Effect.fail(
        new HuntError(
          "HOST_EXEC_DISABLED",
          "Host scanner execution is disabled. Run inside a container/VM or pass --web3-host-exec to Pi.",
        ),
      );
    }
    const { run } = yield* Effect.tryPromise({
      try: () => readRunUnsafe(runId),
      catch: (cause) => toHuntError("STATE_READ_FAILED", cause),
    });
    const spec = yield* Effect.tryPromise({
      try: () => buildCommand(run, input),
      catch: (cause) => toHuntError("BUILD_COMMAND_FAILED", cause),
    });

    const nextState: RunState =
      input.operation === "forge-test" || input.operation === "echidna" || input.operation === "medusa"
        ? "VALIDATING"
        : "ANALYZING";

    yield* Effect.tryPromise({
      try: () =>
        appendEventUnsafe(runId, "tool_started", nextState, {
          operation: input.operation,
          command: spec.displayCommand,
          cwd: spec.cwd,
        }),
      catch: (cause) => toHuntError("LEDGER_WRITE_FAILED", cause),
    });

    const processResult = yield* Effect.tryPromise({
      try: async () => {
        const either = await Effect.runPromise(
          Effect.either(
            ScannerService.pipe(
              Effect.flatMap((s) =>
                s.executeOperation(run, input, {
                  allowHostExec: options.allowHostExec,
                  ...(options.signal !== undefined ? { signal: options.signal } : {}),
                  ...(options.onUpdate !== undefined ? { onUpdate: options.onUpdate } : {}),
                }),
              ),
              Effect.provide(ScannerServiceLive),
            ),
          ),
        );
        if (either._tag === "Left") {
          const error = either.left;
          await appendEventUnsafe(runId, "tool_failed", error.code === "ABORTED" ? "ABORTED" : "FAILED", {
            operation: input.operation,
            command: spec.displayCommand,
            error: error.message,
            code: error.code,
          });
          throw error;
        }
        return either.right;
      },
      catch: (cause: unknown) => toHuntError("TOOL_FAILED", cause),
    });

    const artifacts = yield* Effect.tryPromise({
      try: () => writeOperationArtifacts(runId, input.operation, processResult),
      catch: (cause) => toHuntError("ARTIFACT_WRITE_FAILED", cause),
    });

    yield* Effect.tryPromise({
      try: () =>
        appendEventUnsafe(runId, "tool_finished", nextState, {
          operation: input.operation,
          command: spec.displayCommand,
          exitCode: processResult.exitCode,
          signal: processResult.signal,
          durationMs: processResult.durationMs,
          artifacts,
        }),
      catch: (cause) => toHuntError("LEDGER_WRITE_FAILED", cause),
    });

    return {
      operation: input.operation,
      command: spec.displayCommand,
      exitCode: processResult.exitCode,
      signal: processResult.signal,
      durationMs: processResult.durationMs,
      stdout: processResult.stdout,
      stderr: processResult.stderr,
      artifacts,
    };
  });
}

export async function runOperation(
  runId: string,
  input: OperationInput,
  options: { allowHostExec: boolean; signal?: AbortSignal | undefined; onUpdate?: ((update: OperationUpdate) => void) | undefined },
): Promise<OperationResult> {
  return runHuntEffect(runOperationEffect(runId, input, options));
}

async function copyEvidence(run: HuntRun, findingId: string, evidencePaths: readonly string[]): Promise<Artifact[]> {
  const directory = runDirectory(run.id);
  const artifacts: Artifact[] = [];
  for (let index = 0; index < evidencePaths.length; index++) {
    const requested = cleanText(evidencePaths[index] ?? "", `evidencePaths[${index}]`, 2_000);
    const unresolved = isAbsolute(requested) ? requested : resolve(run.scope.targetRoot, requested);
    const source = await realpath(unresolved);
    if (!isWithin(run.scope.targetRoot, source) && !isWithin(directory, source)) {
      throw new HuntError("OUTSIDE_EVIDENCE_ROOT", "Evidence must be inside the target or current run directory");
    }
    const sourceStat = await stat(source);
    if (!sourceStat.isFile()) throw new HuntError("INVALID_EVIDENCE", `${requested} is not a regular file`);
    if (sourceStat.size > MAX_EVIDENCE_BYTES) {
      throw new HuntError("EVIDENCE_LIMIT", `${requested} exceeds ${MAX_EVIDENCE_BYTES} bytes`);
    }
    const data = await readFile(source);
    const safeName = basename(source).replace(/[^A-Za-z0-9._-]/g, "_");
    const destination = join(directory, "artifacts", `${findingId}-${index + 1}-${safeName}`);
    await atomicWrite(destination, data);
    artifacts.push({ path: destination, sha256: sha256(data), size: data.length });
  }
  return artifacts;
}

function validateFindingInput(input: FindingInput): FindingInput {
  if (!input || typeof input !== "object") throw new HuntError("INVALID_FINDING", "Finding input must be an object");
  if (!["critical", "high", "medium", "low", "informational"].includes(input.severity)) {
    throw new HuntError("INVALID_FINDING", "Invalid severity");
  }
  if (!["candidate", "confirmed", "killed"].includes(input.status)) {
    throw new HuntError("INVALID_FINDING", "Invalid finding status");
  }
  if (!input.gates || typeof input.gates !== "object") throw new HuntError("INVALID_FINDING", "Finding gates are required");
  for (const key of GATE_KEYS) {
    if (typeof input.gates[key] !== "boolean") throw new HuntError("INVALID_FINDING", `Gate ${key} must be boolean`);
  }
  if (!Array.isArray(input.evidencePaths) || input.evidencePaths.length > 32 || input.evidencePaths.some((path) => typeof path !== "string")) {
    throw new HuntError("INVALID_FINDING", "evidencePaths must contain at most 32 file paths");
  }
  const normalized: FindingInput = {
    title: singleLineText(input.title, "title", 300),
    severity: input.severity,
    status: input.status,
    rootCause: cleanText(input.rootCause, "rootCause"),
    impact: cleanText(input.impact, "impact"),
    reproduction: cleanText(input.reproduction, "reproduction", 20_000),
    gates: { ...input.gates },
    evidencePaths: [...input.evidencePaths],
  };
  if (input.status === "confirmed") {
    const failed = GATE_KEYS.filter((key) => !input.gates[key]);
    if (failed.length) throw new HuntError("VALIDATION_FAILED", `Confirmed finding failed gates: ${failed.join(", ")}`);
    if (input.evidencePaths.length === 0) throw new HuntError("VALIDATION_FAILED", "Confirmed findings require evidence files");
  }
  return normalized;
}

export function recordFindingEffect(runId: string, input: FindingInput): Effect.Effect<FindingRecord, HuntError> {
  return Effect.gen(function* () {
    const normalized = yield* Effect.try({
      try: () => validateFindingInput(input),
      catch: (cause) => toHuntError("INVALID_FINDING", cause),
    });
    // ponytail: first-principles 5-atom mechanical gate (scope/permissionless/state/economic/novelty) — no LLM trust
    if (normalized.status === "confirmed") {
      const { validateFiveAtoms } = yield* Effect.promise(() => import("./services/FirstPrinciplesValidator.js"));
      const five = yield* Effect.promise(() => validateFiveAtoms(normalized.evidencePaths, normalized.title));
      if (!five.allPass) {
        return yield* Effect.fail(new HuntError("VALIDATION_FAILED", `First-principles 5-atom check failed: ${five.reasons.join("; ")} — record as killed`));
      }
    }
    const { run, directory } = yield* Effect.tryPromise({
      try: () => readRunUnsafe(runId),
      catch: (cause) => toHuntError("STATE_READ_FAILED", cause),
    });
    const id = `finding-${randomUUID().replaceAll("-", "").slice(0, 12)}`;
    const evidence = yield* Effect.tryPromise({
      try: () => copyEvidence(run, id, normalized.evidencePaths),
      catch: (cause) => toHuntError("EVIDENCE_CAPTURE_FAILED", cause),
    });
    const finding: FindingRecord = {
      ...normalized,
      id,
      runId,
      createdAt: new Date().toISOString(),
      evidence,
    };
    const findingPath = join(directory, "findings", `${id}.json`);
    const findingData = Buffer.from(`${JSON.stringify(finding, null, 2)}\n`, "utf8");
    yield* Effect.tryPromise({
      try: () => atomicWrite(findingPath, findingData),
      catch: (cause) => toHuntError("FINDING_WRITE_FAILED", cause),
    });
    const findingArtifact: Artifact = { path: findingPath, sha256: sha256(findingData), size: findingData.length };
    const state: RunState = finding.status === "confirmed" ? "CONFIRMED" : finding.status === "candidate" ? "VALIDATING" : "ANALYZING";
    yield* Effect.tryPromise({
      try: () =>
        appendEventUnsafe(runId, `finding_${finding.status}`, state, {
          findingId: id,
          title: finding.title,
          severity: finding.severity,
          gates: finding.gates,
          evidence: finding.evidence,
          artifacts: [findingArtifact, ...finding.evidence],
        }),
      catch: (cause) => toHuntError("LEDGER_WRITE_FAILED", cause),
    });
    return finding;
  });
}

export async function recordFinding(runId: string, input: FindingInput): Promise<FindingRecord> {
  return runHuntEffect(recordFindingEffect(runId, input));
}

function artifactsFromEvent(event: HuntEvent): Artifact[] {
  const value = event.data.artifacts;
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is Artifact => {
    if (!item || typeof item !== "object") return false;
    const artifact = item as Partial<Artifact>;
    return typeof artifact.path === "string" && typeof artifact.sha256 === "string" && typeof artifact.size === "number";
  });
}

async function verifyArtifact(directory: string, artifact: Artifact): Promise<Buffer> {
  const candidate = await realpath(artifact.path);
  if (!isWithin(directory, candidate)) throw new HuntError("CORRUPT_ARTIFACT", "Artifact path escapes the run directory");
  const data = await readFile(candidate);
  if (data.length !== artifact.size || sha256(data) !== artifact.sha256) {
    throw new HuntError("CORRUPT_ARTIFACT", `Artifact hash mismatch: ${artifact.path}`);
  }
  return data;
}

async function readFindings(directory: string, runId: string, events: HuntEvent[]): Promise<FindingRecord[]> {
  const findings: FindingRecord[] = [];
  const seen = new Set<string>();
  for (const event of events) {
    const match = /^finding_(candidate|confirmed|killed)$/u.exec(event.type);
    if (!match) continue;
    const id = event.data.findingId;
    if (typeof id !== "string" || !FINDING_ID_PATTERN.test(id) || seen.has(id)) {
      throw new HuntError("CORRUPT_FINDING", "Finding ledger entry has an invalid or duplicate id");
    }
    seen.add(id);
    const path = join(directory, "findings", `${id}.json`);
    const artifact = artifactsFromEvent(event).find((item) => item.path === path);
    if (!artifact) throw new HuntError("CORRUPT_FINDING", `Finding artifact is missing from the ledger: ${id}`);
    const data = await verifyArtifact(directory, artifact);
    const finding = JSON.parse(data.toString("utf8")) as FindingRecord;
    if (finding.id !== id || finding.runId !== runId || finding.status !== match[1]) {
      throw new HuntError("CORRUPT_FINDING", `Finding metadata does not match the ledger: ${id}`);
    }
    findings.push(finding);
  }
  return findings;
}

export function getRunSummaryEffect(runId: string): Effect.Effect<RunSummary, HuntError> {
  return Effect.gen(function* () {
    const { run, directory, events } = yield* Effect.tryPromise({
      try: () => readRunUnsafe(runId),
      catch: (cause) => toHuntError("STATE_READ_FAILED", cause),
    });
    const findings = yield* Effect.tryPromise({
      try: () => readFindings(directory, runId, events),
      catch: (cause) => toHuntError("FINDING_READ_FAILED", cause),
    });
    return {
      run,
      runDirectory: directory,
      findings: {
        candidate: findings.filter((finding) => finding.status === "candidate").length,
        confirmed: findings.filter((finding) => finding.status === "confirmed").length,
        killed: findings.filter((finding) => finding.status === "killed").length,
      },
    };
  });
}

export async function getRunSummary(runId: string): Promise<RunSummary> {
  return runHuntEffect(getRunSummaryEffect(runId));
}

function reportFinding(finding: FindingRecord): string {
  const gates = GATE_KEYS.map((key) => `- [${finding.gates[key] ? "x" : " "}] ${key}`).join("\n");
  const evidence = finding.evidence.length
    ? finding.evidence.map((artifact) => `- \`${artifact.path}\` — SHA-256 \`${artifact.sha256}\``).join("\n")
    : "- None";
  return `## ${finding.title}\n\n**Severity:** ${finding.severity}\n\n### Root cause\n\n${finding.rootCause}\n\n### Impact\n\n${finding.impact}\n\n### Reproduction\n\n${finding.reproduction}\n\n### Validation gates\n\n${gates}\n\n### Evidence\n\n${evidence}\n`;
}

export function buildReportEffect(runId: string): Effect.Effect<string, HuntError> {
  return Effect.gen(function* () {
    yield* verifyRunEffect(runId);
    const { run, directory, events } = yield* Effect.tryPromise({
      try: () => readRunUnsafe(runId),
      catch: (cause) => toHuntError("STATE_READ_FAILED", cause),
    });
    const findings = yield* Effect.tryPromise({
      try: () => readFindings(directory, runId, events),
      catch: (cause) => toHuntError("FINDING_READ_FAILED", cause),
    });
    const confirmed = findings.filter((finding) => finding.status === "confirmed");
    const content = [
      "# Web3 Security Hunt Report",
      "",
      `- Run: \`${run.id}\``,
      `- Program: ${run.scope.program}`,
      `- Target: \`${run.scope.target}\``,
      `- Chain ID: ${run.scope.chainId ?? "local/source audit"}`,
      `- Evidence ledger: \`${join(directory, "events.jsonl")}\``,
      "",
      confirmed.length ? confirmed.map(reportFinding).join("\n") : "## Result\n\nNo finding passed all validation gates.",
      "",
      "## Scope note",
      "",
      "Testing was performed under the user's authorization attestation. Reproduction should remain on local forks or test environments unless the bounty program explicitly permits otherwise.",
      "",
    ].join("\n");
    const path = join(directory, `report-${Date.now()}-${randomUUID().replaceAll("-", "").slice(0, 8)}.md`);
    const reportData = Buffer.from(content, "utf8");
    yield* Effect.tryPromise({
      try: () => atomicWrite(path, reportData),
      catch: (cause) => toHuntError("REPORT_WRITE_FAILED", cause),
    });
    const artifact: Artifact = { path, sha256: sha256(reportData), size: reportData.length };
    yield* Effect.tryPromise({
      try: () =>
        appendEventUnsafe(runId, "report_ready", "REPORT_READY", {
          reportPath: path,
          confirmedFindings: confirmed.length,
          artifacts: [artifact],
        }),
      catch: (cause) => toHuntError("LEDGER_WRITE_FAILED", cause),
    });
    return path;
  });
}

export async function buildReport(runId: string): Promise<string> {
  return runHuntEffect(buildReportEffect(runId));
}

export function verifyRunEffect(runId: string): Effect.Effect<VerificationResult, HuntError> {
  return Effect.gen(function* () {
    const { directory, events } = yield* Effect.tryPromise({
      try: () => readRunUnsafe(runId),
      catch: (cause) => toHuntError("VERIFY_FAILED", cause),
    });
    yield* Effect.tryPromise({
      try: () => readFindings(directory, runId, events),
      catch: (cause) => toHuntError("VERIFY_FAILED", cause),
    });
    const artifacts = events.flatMap(artifactsFromEvent);
    const unique = new Map<string, Artifact>();
    for (const artifact of artifacts) {
      const previous = unique.get(artifact.path);
      if (previous && (previous.sha256 !== artifact.sha256 || previous.size !== artifact.size)) {
        return yield* Effect.fail(new HuntError("CORRUPT_ARTIFACT", `Conflicting artifact records: ${artifact.path}`));
      }
      unique.set(artifact.path, artifact);
    }
    for (const artifact of unique.values()) {
      yield* Effect.tryPromise({
        try: () => verifyArtifact(directory, artifact),
        catch: (cause) => toHuntError("VERIFY_FAILED", cause),
      });
    }
    return {
      valid: true,
      eventCount: events.length,
      artifactCount: unique.size,
      lastEventHash: events.at(-1)?.hash ?? "GENESIS",
    };
  });
}

export async function verifyRun(runId: string): Promise<VerificationResult> {
  return runHuntEffect(verifyRunEffect(runId));
}

export function formatRunSummary(summary: RunSummary): string {
  return [
    `Run: ${summary.run.id}`,
    `State: ${summary.run.state}`,
    `Target: ${summary.run.scope.target}`,
    `Program: ${summary.run.scope.program}`,
    `Findings: ${summary.findings.confirmed} confirmed, ${summary.findings.candidate} candidate, ${summary.findings.killed} killed`,
    `Evidence: ${summary.runDirectory}`,
  ].join("\n");
}

export function resolveContractSourceEffect(
  address: string,
  chainId: number,
  targetDir: string,
): Effect.Effect<{ sourceFound: boolean; path: string; files: string[]; contractName?: string | undefined }, HuntError> {
  return Effect.gen(function* () {
    const multiChain = yield* MultiChainService;
    return yield* multiChain.resolveContractSource(address, chainId, targetDir);
  }).pipe(Effect.provide(MultiChainServiceLive));
}

export async function resolveContractSource(
  address: string,
  chainId: number,
  targetDir: string,
): Promise<{ sourceFound: boolean; path: string; files: string[]; contractName?: string | undefined }> {
  return runHuntEffect(resolveContractSourceEffect(address, chainId, targetDir));
}

export function searchReconTargetsEffect(
  options?: ReconQueryOptions,
): Effect.Effect<ProtocolTarget[], HuntError> {
  return Effect.gen(function* () {
    const recon = yield* ReconService;
    return yield* recon.searchTargets(options);
  }).pipe(Effect.provide(ReconServiceLive));
}

export async function searchReconTargets(options?: ReconQueryOptions): Promise<ProtocolTarget[]> {
  return runHuntEffect(searchReconTargetsEffect(options));
}

export function getReconTargetEffect(id: string): Effect.Effect<ProtocolTarget, HuntError> {
  return Effect.gen(function* () {
    const recon = yield* ReconService;
    return yield* recon.getTargetById(id);
  }).pipe(Effect.provide(ReconServiceLive));
}

export async function getReconTarget(id: string): Promise<ProtocolTarget> {
  return runHuntEffect(getReconTargetEffect(id));
}

export function pickAutoTargetEffect(
  query?: string,
  preferredChainId?: number,
  excludeTargetIds?: string[],
): Effect.Effect<AutoTargetSelection, HuntError> {
  return Effect.gen(function* () {
    const recon = yield* ReconService;
    return yield* recon.pickAutoTarget(query, preferredChainId, excludeTargetIds);
  }).pipe(Effect.provide(ReconServiceLive));
}

export async function pickAutoTarget(
  query?: string,
  preferredChainId?: number,
  excludeTargetIds?: string[],
): Promise<AutoTargetSelection> {
  return runHuntEffect(pickAutoTargetEffect(query, preferredChainId, excludeTargetIds));
}



