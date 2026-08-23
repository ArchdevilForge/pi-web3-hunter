import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  appendFile,
  chmod,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { spawn } from "node:child_process";
import { Effect } from "effect";

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 10 * 1024 * 1024;
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 5_000;
const RUN_ID_PATTERN = /^run-[0-9]{8}t[0-9]{6}z-[a-f0-9]{8}$/;
const FINDING_ID_PATTERN = /^finding-[a-f0-9]{12}$/;
const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;

export const RUN_STATES = [
  "SCOPED",
  "ANALYZING",
  "VALIDATING",
  "CONFIRMED",
  "REPORT_READY",
  "ABORTED",
  "FAILED",
] as const;

export const OPERATIONS = ["forge-build", "forge-test", "slither", "echidna", "medusa", "cast-code"] as const;

export const GATE_KEYS = [
  "reproduced",
  "impactInScope",
  "rootCauseInScope",
  "realisticAttacker",
  "notKnownOrIntended",
  "impactDemonstrated",
  "pinnedAndRepeatable",
] as const;

export type RunState = (typeof RUN_STATES)[number];
export type Operation = (typeof OPERATIONS)[number];
export type FindingStatus = "candidate" | "confirmed" | "killed";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export class HuntError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "HuntError";
    this.code = code;
  }
}

export interface ScopeInput {
  cwd: string;
  target: string;
  program: string;
  authorized: boolean;
  chainId?: number;
  rpcUrl?: string;
}

export interface ScopeManifest {
  kind: "repository" | "contract";
  target: string;
  targetRoot: string;
  program: string;
  authorization: "user-attested";
  chainId?: number;
  rpcHost?: string;
  createdAt: string;
}

export interface HuntRun {
  version: 1;
  id: string;
  state: RunState;
  scope: ScopeManifest;
  createdAt: string;
  updatedAt: string;
  eventCount: number;
  lastEventHash: string;
}

export interface HuntEvent {
  sequence: number;
  timestamp: string;
  type: string;
  state: RunState;
  data: Record<string, unknown>;
  previousHash: string;
  hash: string;
}

export interface ToolCapability {
  name: "forge" | "anvil" | "cast" | "slither" | "echidna" | "medusa" | "docker";
  available: boolean;
  path?: string;
}

export interface OperationInput {
  operation: Operation;
  matchPath?: string;
  matchContract?: string;
  matchTest?: string;
  contractPath?: string;
  contractName?: string;
  configPath?: string;
  forkBlockNumber?: number;
  timeoutMs?: number;
}

export interface OperationUpdate {
  stream: "stdout" | "stderr";
  text: string;
}

export interface Artifact {
  path: string;
  sha256: string;
  size: number;
}

export interface OperationResult {
  operation: Operation;
  command: string[];
  exitCode: number;
  signal: NodeJS.Signals | null;
  durationMs: number;
  stdout: string;
  stderr: string;
  artifacts: Artifact[];
}

export interface ValidationGates {
  reproduced: boolean;
  impactInScope: boolean;
  rootCauseInScope: boolean;
  realisticAttacker: boolean;
  notKnownOrIntended: boolean;
  impactDemonstrated: boolean;
  pinnedAndRepeatable: boolean;
}

export interface FindingInput {
  title: string;
  severity: Severity;
  status: FindingStatus;
  rootCause: string;
  impact: string;
  reproduction: string;
  gates: ValidationGates;
  evidencePaths: string[];
}

export interface FindingRecord extends FindingInput {
  id: string;
  runId: string;
  createdAt: string;
  evidence: Artifact[];
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

interface CommandSpec {
  executable: string;
  args: string[];
  displayCommand: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
}

interface ProcessResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
  durationMs: number;
  stdout: string;
  stderr: string;
}

const TRANSITIONS: Record<RunState, ReadonlySet<RunState>> = {
  SCOPED: new Set(["SCOPED", "ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  ANALYZING: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  VALIDATING: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  CONFIRMED: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  REPORT_READY: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  ABORTED: new Set(["ANALYZING", "VALIDATING", "REPORT_READY", "ABORTED"]),
  FAILED: new Set(["ANALYZING", "VALIDATING", "REPORT_READY", "ABORTED", "FAILED"]),
};

function toHuntError(code: string, cause: unknown): HuntError {
  if (cause instanceof HuntError) return cause;
  const message = cause instanceof Error ? cause.message : String(cause);
  return new HuntError(code, message, cause instanceof Error ? { cause } : undefined);
}

function attempt<T>(code: string, work: () => Promise<T>): Effect.Effect<T, HuntError> {
  return Effect.tryPromise({ try: work, catch: (cause) => toHuntError(code, cause) });
}

async function runHuntEffect<T>(effect: Effect.Effect<T, HuntError>): Promise<T> {
  const result = await Effect.runPromise(Effect.either(effect));
  if (result._tag === "Left") throw result.left;
  return result.right;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonical(item)]),
    );
  }
  return value;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function hashEvent(event: Omit<HuntEvent, "hash">): string {
  return sha256(JSON.stringify(canonical(event)));
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

function assertRunId(runId: string): void {
  if (!RUN_ID_PATTERN.test(runId)) throw new HuntError("INVALID_RUN_ID", "Invalid run id");
}

function isWithin(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value === "" || (!value.startsWith(`..${sep}`) && value !== ".." && !isAbsolute(value));
}

function stateRoot(): string {
  const configured = process.env.WEB3_HUNTER_STATE_DIR;
  if (configured) return resolve(configured);
  const xdgState = process.env.XDG_STATE_HOME;
  return join(xdgState ? resolve(xdgState) : join(homedir(), ".local", "state"), "pi-web3-hunter");
}

export function getStateRoot(): string {
  return stateRoot();
}

function runDirectory(runId: string): string {
  assertRunId(runId);
  return join(stateRoot(), "runs", runId);
}

async function atomicWrite(path: string, data: string | Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, data, { flag: "wx", mode: 0o600 });
  await rename(temporary, path);
  await chmod(path, 0o600);
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, ms));
}

async function withRunLock<T>(directory: string, work: () => Promise<T>): Promise<T> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lockPath = join(directory, ".lock");
  const started = Date.now();
  let handle: Awaited<ReturnType<typeof open>> | undefined;

  while (!handle) {
    try {
      handle = await open(lockPath, "wx", 0o600);
      await handle.writeFile(`${process.pid}\n`);
    } catch (error) {
      const cause = error as NodeJS.ErrnoException;
      if (cause.code !== "EEXIST") throw error;
      try {
        const lockStat = await stat(lockPath);
        if (Date.now() - lockStat.mtimeMs > LOCK_STALE_MS) {
          await unlink(lockPath);
          continue;
        }
      } catch (lockError) {
        if ((lockError as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw lockError;
      }
      if (Date.now() - started > LOCK_WAIT_MS) throw new HuntError("RUN_BUSY", "Run is locked by another process");
      await delay(50);
    }
  }

  try {
    return await work();
  } finally {
    await handle.close();
    try {
      await unlink(lockPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

function assertTransition(current: RunState, next: RunState): void {
  if (!TRANSITIONS[current].has(next)) {
    throw new HuntError("INVALID_STATE", `Invalid run transition: ${current} -> ${next}`);
  }
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

function verifyEventChain(events: HuntEvent[]): void {
  let previousHash = "GENESIS";
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    if (!event) throw new HuntError("CORRUPT_LEDGER", `Missing event ${index + 1}`);
    if (event.sequence !== index + 1) throw new HuntError("CORRUPT_LEDGER", `Invalid sequence at event ${index + 1}`);
    if (event.previousHash !== previousHash) throw new HuntError("CORRUPT_LEDGER", `Broken hash link at event ${index + 1}`);
    const { hash, ...unsigned } = event;
    if (hashEvent(unsigned) !== hash) throw new HuntError("CORRUPT_LEDGER", `Hash mismatch at event ${index + 1}`);
    previousHash = hash;
  }
}

async function readRunUnsafe(runId: string): Promise<{ run: HuntRun; directory: string; events: HuntEvent[] }> {
  assertRunId(runId);
  const directory = runDirectory(runId);
  const run = await readJson<HuntRun>(join(directory, "run.json"));
  if (run.id !== runId || run.version !== 1) throw new HuntError("CORRUPT_RUN", "Run metadata does not match the requested id");
  const events = await readEvents(directory);
  verifyEventChain(events);
  const last = events.at(-1);
  if (last) {
    run.state = last.state;
    run.updatedAt = last.timestamp;
    run.eventCount = events.length;
    run.lastEventHash = last.hash;
  }
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
    const run = await readJson<HuntRun>(join(directory, "run.json"));
    assertTransition(run.state, state);
    const events = await readEvents(directory);
    verifyEventChain(events);
    const last = events.at(-1);
    const unsigned: Omit<HuntEvent, "hash"> = {
      sequence: events.length + 1,
      timestamp: new Date().toISOString(),
      type: cleanText(type, "event type", 100),
      state,
      data,
      previousHash: last?.hash ?? "GENESIS",
    };
    const event: HuntEvent = { ...unsigned, hash: hashEvent(unsigned) };
    await appendFile(join(directory, "events.jsonl"), `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
    run.state = state;
    run.updatedAt = event.timestamp;
    run.eventCount = event.sequence;
    run.lastEventHash = event.hash;
    await atomicWrite(join(directory, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
    return event;
  });
}

function normalizedRpcHost(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new HuntError("INVALID_RPC", "RPC URL is invalid", { cause });
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new HuntError("INVALID_RPC", "RPC URL must use http or https");
  }
  return `${url.protocol}//${url.host}`;
}

async function resolveScope(input: ScopeInput): Promise<ScopeManifest> {
  if (!input.authorized) {
    throw new HuntError("AUTHORIZATION_REQUIRED", "Explicit authorization is required before a hunt can start");
  }
  const program = singleLineText(input.program, "program", 300);
  const workspace = await realpath(resolve(input.cwd));
  const createdAt = new Date().toISOString();

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

  const candidate = await realpath(resolve(workspace, input.target));
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

export function createRunEffect(input: ScopeInput): Effect.Effect<HuntRun, HuntError> {
  return Effect.gen(function* () {
    const scope = yield* attempt("SCOPE_ERROR", () => resolveScope(input));
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
    yield* attempt("STATE_WRITE_FAILED", async () => {
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
    });
    return (yield* attempt("STATE_READ_FAILED", async () => (await readRunUnsafe(run.id)).run));
  });
}

export async function createRun(input: ScopeInput): Promise<HuntRun> {
  return runHuntEffect(createRunEffect(input));
}

async function findExecutable(name: string, excludedRoot?: string): Promise<string | undefined> {
  for (const directory of (process.env.PATH ?? "").split(delimiter).filter(Boolean)) {
    if (!isAbsolute(directory)) continue;
    try {
      const candidate = await realpath(join(directory, name));
      if (excludedRoot && isWithin(excludedRoot, candidate)) continue;
      if (!(await stat(candidate)).isFile()) continue;
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Continue through PATH.
    }
  }
  return undefined;
}

export function preflightEffect(): Effect.Effect<ToolCapability[], HuntError> {
  const tools = ["forge", "anvil", "cast", "slither", "echidna", "medusa", "docker"] as const;
  return Effect.forEach(
    tools,
    (name) => attempt("PREFLIGHT_FAILED", async () => {
      const path = await findExecutable(name);
      return { name, available: Boolean(path), ...(path ? { path } : {}) };
    }),
    { concurrency: 4 },
  );
}

export async function preflight(): Promise<ToolCapability[]> {
  return runHuntEffect(preflightEffect());
}

function safeSelector(value: string | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  return singleLineText(value, label, 300);
}

async function pathInside(root: string, value: string, label: string): Promise<string> {
  const candidate = await realpath(resolve(root, value));
  if (!isWithin(root, candidate)) throw new HuntError("OUTSIDE_TARGET", `${label} escapes the target repository`);
  return candidate;
}

function processEnvironment(rpcUrl?: string): NodeJS.ProcessEnv {
  const allowedKeys = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR"];
  const env: NodeJS.ProcessEnv = { CI: "1", NO_COLOR: "1" };
  for (const key of allowedKeys) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  if (rpcUrl) env.ETH_RPC_URL = rpcUrl;
  return env;
}

async function buildCommand(run: HuntRun, input: OperationInput): Promise<CommandSpec> {
  if (!OPERATIONS.includes(input.operation)) throw new HuntError("INVALID_OPERATION", "Unsupported operation");
  const root = run.scope.targetRoot;
  const timeoutMs = input.timeoutMs ?? 300_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 900_000) {
    throw new HuntError("INVALID_TIMEOUT", "timeoutMs must be between 1000 and 900000");
  }

  switch (input.operation) {
    case "forge-build":
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "forge-build requires a repository target");
      return { executable: "forge", args: ["build"], displayCommand: ["forge", "build"], cwd: root, env: processEnvironment() };

    case "forge-test": {
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "forge-test requires a repository target");
      const args = ["test"];
      const matchPath = safeSelector(input.matchPath, "matchPath");
      const matchContract = safeSelector(input.matchContract, "matchContract");
      const matchTest = safeSelector(input.matchTest, "matchTest");
      if (matchPath) args.push("--match-path", matchPath);
      if (matchContract) args.push("--match-contract", matchContract);
      if (matchTest) args.push("--match-test", matchTest);
      if (input.forkBlockNumber !== undefined) {
        if (!Number.isSafeInteger(input.forkBlockNumber) || input.forkBlockNumber < 0) {
          throw new HuntError("INVALID_BLOCK", "forkBlockNumber must be a non-negative integer");
        }
        args.push("--fork-block-number", String(input.forkBlockNumber));
      }
      args.push("-vvv");
      return { executable: "forge", args, displayCommand: ["forge", ...args], cwd: root, env: processEnvironment(process.env.WEB3_HUNTER_RPC_URL) };
    }

    case "slither":
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "slither requires a repository target");
      return {
        executable: "slither",
        args: [".", "--json", "-"],
        displayCommand: ["slither", ".", "--json", "-"],
        cwd: root,
        env: processEnvironment(),
      };

    case "echidna": {
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "echidna requires a repository target");
      if (!input.contractPath || !input.contractName) {
        throw new HuntError("INVALID_INPUT", "echidna requires contractPath and contractName");
      }
      const contractPath = await pathInside(root, input.contractPath, "contractPath");
      if (!IDENTIFIER_PATTERN.test(input.contractName)) throw new HuntError("INVALID_INPUT", "Invalid Solidity contract name");
      const args = [contractPath, "--contract", input.contractName, "--format", "json"];
      if (input.configPath) args.push("--config", await pathInside(root, input.configPath, "configPath"));
      return { executable: "echidna", args, displayCommand: ["echidna", ...args], cwd: root, env: processEnvironment() };
    }

    case "medusa": {
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "medusa requires a repository target");
      const args = ["fuzz"];
      if (input.configPath) args.push("--config", await pathInside(root, input.configPath, "configPath"));
      return { executable: "medusa", args, displayCommand: ["medusa", ...args], cwd: root, env: processEnvironment() };
    }

    case "cast-code": {
      if (run.scope.kind !== "contract") throw new HuntError("INVALID_TARGET", "cast-code requires a contract target");
      const rpcUrl = process.env.WEB3_HUNTER_RPC_URL;
      if (!rpcUrl) throw new HuntError("RPC_REQUIRED", "Set WEB3_HUNTER_RPC_URL before using cast-code");
      normalizedRpcHost(rpcUrl);
      const args = ["code", run.scope.target];
      return {
        executable: "cast",
        args,
        displayCommand: ["cast", "code", run.scope.target],
        cwd: root,
        env: processEnvironment(rpcUrl),
      };
    }
  }
}

function killProcess(child: ReturnType<typeof spawn>): void {
  if (!child.pid || child.killed) return;
  try {
    if (process.platform === "win32") child.kill("SIGTERM");
    else process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  const timer = setTimeout(() => {
    try {
      if (process.platform === "win32") child.kill("SIGKILL");
      else if (child.pid) process.kill(-child.pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  }, 2_000);
  timer.unref();
}

async function runProcess(
  spec: CommandSpec,
  timeoutMs: number,
  signal?: AbortSignal,
  onUpdate?: (update: OperationUpdate) => void,
): Promise<ProcessResult> {
  const executable = await findExecutable(spec.executable, spec.cwd);
  if (!executable) throw new HuntError("TOOL_MISSING", `${spec.executable} is not installed or not on PATH`);
  if (signal?.aborted) throw new HuntError("ABORTED", "Operation aborted before execution");

  return new Promise<ProcessResult>((resolveProcess, rejectProcess) => {
    const started = Date.now();
    const child = spawn(executable, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let finished = false;
    let failure: HuntError | undefined;
    let lastUpdate = 0;

    const finishError = (error: HuntError) => {
      if (!failure) failure = error;
      killProcess(child);
    };
    const capture = (stream: "stdout" | "stderr", chunk: Buffer) => {
      if (stream === "stdout") {
        stdoutBytes += chunk.length;
        if (stdoutBytes <= MAX_OUTPUT_BYTES) stdout.push(chunk);
        else finishError(new HuntError("OUTPUT_LIMIT", `stdout exceeded ${MAX_OUTPUT_BYTES} bytes`));
      } else {
        stderrBytes += chunk.length;
        if (stderrBytes <= MAX_OUTPUT_BYTES) stderr.push(chunk);
        else finishError(new HuntError("OUTPUT_LIMIT", `stderr exceeded ${MAX_OUTPUT_BYTES} bytes`));
      }
      const now = Date.now();
      if (onUpdate && now - lastUpdate >= 200) {
        lastUpdate = now;
        onUpdate({ stream, text: chunk.toString("utf8").slice(-2_000) });
      }
    };

    child.stdout?.on("data", (chunk: Buffer) => capture("stdout", chunk));
    child.stderr?.on("data", (chunk: Buffer) => capture("stderr", chunk));

    const timeout = setTimeout(() => finishError(new HuntError("TIMEOUT", `Operation timed out after ${timeoutMs}ms`)), timeoutMs);
    const abort = () => finishError(new HuntError("ABORTED", "Operation aborted"));
    signal?.addEventListener("abort", abort, { once: true });

    child.once("error", (cause) => finishError(new HuntError("SPAWN_FAILED", cause.message, { cause })));
    child.once("close", (exitCode, exitSignal) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      if (failure) {
        rejectProcess(failure);
        return;
      }
      resolveProcess({
        exitCode: exitCode ?? -1,
        signal: exitSignal,
        durationMs: Date.now() - started,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

async function writeOperationArtifacts(runId: string, operation: Operation, result: ProcessResult): Promise<Artifact[]> {
  const directory = runDirectory(runId);
  const prefix = `${Date.now()}-${randomUUID().replaceAll("-", "").slice(0, 8)}-${operation}`;
  const values: Array<[string, string]> = [
    [`${prefix}.stdout.txt`, result.stdout],
    [`${prefix}.stderr.txt`, result.stderr],
  ];
  const artifacts: Artifact[] = [];
  for (const [name, content] of values) {
    const data = Buffer.from(content, "utf8");
    const path = join(directory, "artifacts", name);
    await atomicWrite(path, data);
    artifacts.push({ path, sha256: sha256(data), size: data.length });
  }
  return artifacts;
}

export function runOperationEffect(
  runId: string,
  input: OperationInput,
  options: { allowHostExec: boolean; signal?: AbortSignal; onUpdate?: (update: OperationUpdate) => void },
): Effect.Effect<OperationResult, HuntError> {
  return Effect.gen(function* () {
    if (!options.allowHostExec) {
      return yield* Effect.fail(
        new HuntError(
          "HOST_EXEC_DISABLED",
          "Scanner execution is disabled. Run Pi in an isolated environment and pass --web3-host-exec.",
        ),
      );
    }
    const { run } = yield* attempt("STATE_READ_FAILED", () => readRunUnsafe(runId));
    const spec = yield* attempt("INVALID_OPERATION", () => buildCommand(run, input));
    const nextState: RunState = input.operation === "forge-test" || input.operation === "echidna" || input.operation === "medusa"
      ? "VALIDATING"
      : "ANALYZING";
    yield* attempt("LEDGER_WRITE_FAILED", () => appendEventUnsafe(runId, "tool_started", nextState, {
      operation: input.operation,
      command: spec.displayCommand,
    }));

    const timeoutMs = input.timeoutMs ?? 300_000;
    const processResult = yield* attempt("TOOL_FAILED", async () => {
      try {
        return await runProcess(spec, timeoutMs, options.signal, options.onUpdate);
      } catch (cause) {
        const error = toHuntError("TOOL_FAILED", cause);
        await appendEventUnsafe(runId, "tool_failed", error.code === "ABORTED" ? "ABORTED" : "FAILED", {
          operation: input.operation,
          command: spec.displayCommand,
          error: error.message,
          code: error.code,
        });
        throw error;
      }
    });
    const artifacts = yield* attempt("ARTIFACT_WRITE_FAILED", () => writeOperationArtifacts(runId, input.operation, processResult));
    yield* attempt("LEDGER_WRITE_FAILED", () => appendEventUnsafe(runId, "tool_finished", nextState, {
      operation: input.operation,
      command: spec.displayCommand,
      exitCode: processResult.exitCode,
      signal: processResult.signal,
      durationMs: processResult.durationMs,
      artifacts,
    }));
    return {
      operation: input.operation,
      command: spec.displayCommand,
      ...processResult,
      artifacts,
    };
  });
}

export async function runOperation(
  runId: string,
  input: OperationInput,
  options: { allowHostExec: boolean; signal?: AbortSignal; onUpdate?: (update: OperationUpdate) => void },
): Promise<OperationResult> {
  return runHuntEffect(runOperationEffect(runId, input, options));
}

async function copyEvidence(run: HuntRun, findingId: string, evidencePaths: string[]): Promise<Artifact[]> {
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
    const normalized = yield* Effect.try({ try: () => validateFindingInput(input), catch: (cause) => toHuntError("INVALID_FINDING", cause) });
    const { run, directory } = yield* attempt("STATE_READ_FAILED", () => readRunUnsafe(runId));
    const id = `finding-${randomUUID().replaceAll("-", "").slice(0, 12)}`;
    const evidence = yield* attempt("EVIDENCE_CAPTURE_FAILED", () => copyEvidence(run, id, normalized.evidencePaths));
    const finding: FindingRecord = {
      ...normalized,
      id,
      runId,
      createdAt: new Date().toISOString(),
      evidence,
    };
    const findingPath = join(directory, "findings", `${id}.json`);
    const findingData = Buffer.from(`${JSON.stringify(finding, null, 2)}\n`, "utf8");
    yield* attempt("FINDING_WRITE_FAILED", () => atomicWrite(findingPath, findingData));
    const findingArtifact: Artifact = { path: findingPath, sha256: sha256(findingData), size: findingData.length };
    const state: RunState = finding.status === "confirmed" ? "CONFIRMED" : finding.status === "candidate" ? "VALIDATING" : "ANALYZING";
    yield* attempt("LEDGER_WRITE_FAILED", () => appendEventUnsafe(runId, `finding_${finding.status}`, state, {
      findingId: id,
      title: finding.title,
      severity: finding.severity,
      gates: finding.gates,
      evidence: finding.evidence,
      artifacts: [findingArtifact, ...finding.evidence],
    }));
    return finding;
  });
}

export async function recordFinding(runId: string, input: FindingInput): Promise<FindingRecord> {
  return runHuntEffect(recordFindingEffect(runId, input));
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
    const { run, directory, events } = yield* attempt("STATE_READ_FAILED", () => readRunUnsafe(runId));
    const findings = yield* attempt("FINDING_READ_FAILED", () => readFindings(directory, runId, events));
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
    const { run, directory, events } = yield* attempt("STATE_READ_FAILED", () => readRunUnsafe(runId));
    const findings = yield* attempt("FINDING_READ_FAILED", () => readFindings(directory, runId, events));
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
    yield* attempt("REPORT_WRITE_FAILED", () => atomicWrite(path, reportData));
    const artifact: Artifact = { path, sha256: sha256(reportData), size: reportData.length };
    yield* attempt("LEDGER_WRITE_FAILED", () => appendEventUnsafe(runId, "report_ready", "REPORT_READY", {
      reportPath: path,
      confirmedFindings: confirmed.length,
      artifacts: [artifact],
    }));
    return path;
  });
}

export async function buildReport(runId: string): Promise<string> {
  return runHuntEffect(buildReportEffect(runId));
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

export function verifyRunEffect(runId: string): Effect.Effect<VerificationResult, HuntError> {
  return Effect.gen(function* () {
    const { directory, events } = yield* attempt("VERIFY_FAILED", () => readRunUnsafe(runId));
    yield* attempt("VERIFY_FAILED", () => readFindings(directory, runId, events));
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
      yield* attempt("VERIFY_FAILED", () => verifyArtifact(directory, artifact));
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
