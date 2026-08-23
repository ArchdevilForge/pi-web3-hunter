import { Context, Effect, Layer } from "effect";
import { spawn } from "node:child_process";
import { access, constants, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";
import { HuntError, toHuntError } from "../errors.js";
import {
  Artifact,
  HuntRun,
  Operation,
  OperationInput,
  OperationResult,
  OPERATIONS,
  ToolCapability,
} from "../schema.js";

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;

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

async function pathInside(root: string, value: string, label: string): Promise<string> {
  const candidate = await realpath(resolve(root, value));
  if (!isWithin(root, candidate)) throw new HuntError("OUTSIDE_TARGET", `${label} escapes the target repository`);
  return candidate;
}

function safeSelector(value: string | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  return singleLineText(value, label, 300);
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

export async function findExecutable(name: string, targetRoot?: string): Promise<string | undefined> {
  const pathEntries = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  for (const entry of pathEntries) {
    if (!isAbsolute(entry)) continue;
    try {
      const candidate = await realpath(join(entry, process.platform === "win32" ? `${name}.exe` : name));
      if (targetRoot && isWithin(targetRoot, candidate)) continue;
      const fileStat = await stat(candidate);
      if (!fileStat.isFile()) continue;
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Continue through PATH.
    }
  }
  return undefined;
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
  onUpdate?: (update: { stream: "stdout" | "stderr"; text: string }) => void,
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

export async function buildCommand(run: HuntRun, input: OperationInput): Promise<CommandSpec> {
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

    case "aderyn":
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "aderyn requires a repository target");
      return {
        executable: "aderyn",
        args: [".", "--output", "report.json"],
        displayCommand: ["aderyn", ".", "--output", "report.json"],
        cwd: root,
        env: processEnvironment(),
      };

    case "halmos": {
      if (run.scope.kind !== "repository") throw new HuntError("INVALID_TARGET", "halmos requires a repository target");
      const args: string[] = [];
      const matchContract = safeSelector(input.matchContract, "matchContract");
      const matchTest = safeSelector(input.matchTest, "matchTest");
      if (matchContract) args.push("--match-contract", matchContract);
      if (matchTest) args.push("--match-test", matchTest);
      return { executable: "halmos", args, displayCommand: ["halmos", ...args], cwd: root, env: processEnvironment() };
    }

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

export class ScannerService extends Context.Tag("ScannerService")<
  ScannerService,
  {
    readonly preflight: () => Effect.Effect<ToolCapability[], HuntError>;
    readonly executeOperation: (
      run: HuntRun,
      input: OperationInput,
      options?: {
        allowHostExec?: boolean | undefined;
        signal?: AbortSignal | undefined;
        onUpdate?: ((update: { stream: "stdout" | "stderr"; text: string }) => void) | undefined;
      } | undefined,
    ) => Effect.Effect<ProcessResult & { command: CommandSpec }, HuntError>;
  }
>() {}

export const ScannerServiceLive = Layer.succeed(
  ScannerService,
  ScannerService.of({
    preflight: () =>
      Effect.gen(function* () {
        const tools = ["forge", "anvil", "cast", "slither", "aderyn", "halmos", "echidna", "medusa", "docker"] as const;
        return yield* Effect.forEach(
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
      }),

    executeOperation: (run, input, options) =>
      Effect.gen(function* () {
        if (!options?.allowHostExec) {
          return yield* Effect.fail(new HuntError("HOST_EXEC_DISABLED", "Scanner execution requires --web3-host-exec / allowHostExec"));
        }
        const command = yield* Effect.tryPromise({
          try: () => buildCommand(run, input),
          catch: (cause) => toHuntError("BUILD_COMMAND_FAILED", cause),
        });

        const result = yield* Effect.tryPromise({
          try: () => runProcess(command, input.timeoutMs ?? 300_000, options?.signal, options?.onUpdate),
          catch: (cause) => toHuntError("EXECUTE_OPERATION_FAILED", cause),
        });

        return { ...result, command };
      }),
  }),
);
