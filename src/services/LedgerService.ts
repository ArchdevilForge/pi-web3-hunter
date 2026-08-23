import { Context, Effect, Layer } from "effect";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { HuntError, toHuntError } from "../errors.js";
import {
  Artifact,
  HuntEvent,
  HuntRun,
  RunState,
} from "../schema.js";

const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 5_000;
const RUN_ID_PATTERN = /^run-[0-9]{8}t[0-9]{6}z-[a-f0-9]{8}$/;

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

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function hashEvent(event: Omit<HuntEvent, "hash">): string {
  return sha256(JSON.stringify(canonical(event)));
}

export function assertRunId(runId: string): void {
  if (!RUN_ID_PATTERN.test(runId)) {
    throw new HuntError("INVALID_RUN_ID", "Invalid run id");
  }
}

export function stateRoot(): string {
  const configured = process.env.WEB3_HUNTER_STATE_DIR;
  if (configured) return resolve(configured);
  const xdgState = process.env.XDG_STATE_HOME;
  return join(xdgState ? resolve(xdgState) : join(homedir(), ".local", "state"), "pi-web3-hunter");
}

export function runDirectory(runId: string): string {
  assertRunId(runId);
  return join(stateRoot(), "runs", runId);
}

export async function atomicWrite(path: string, data: string | Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, data, { flag: "wx", mode: 0o600 });
  await rename(temporary, path);
  await chmod(path, 0o600);
}

export async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, ms));
}

export async function withRunLock<T>(directory: string, work: () => Promise<T>): Promise<T> {
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
      if (Date.now() - started > LOCK_WAIT_MS) {
        throw new HuntError("RUN_BUSY", "Run is locked by another process");
      }
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

export function verifyEventChain(events: HuntEvent[]): void {
  let previousHash = "GENESIS";
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    if (!event) throw new HuntError("CORRUPT_LEDGER", `Missing event ${index + 1}`);
    if (event.sequence !== index + 1) {
      throw new HuntError("CORRUPT_LEDGER", `Invalid sequence at event ${index + 1}`);
    }
    if (event.previousHash !== previousHash) {
      throw new HuntError("CORRUPT_LEDGER", `Broken hash link at event ${index + 1}`);
    }
    const { hash, ...unsigned } = event;
    if (hashEvent(unsigned) !== hash) {
      throw new HuntError("CORRUPT_LEDGER", `Hash mismatch at event ${index + 1}`);
    }
    previousHash = hash;
  }
}

export class LedgerService extends Context.Tag("LedgerService")<
  LedgerService,
  {
    readonly initRun: (run: HuntRun) => Effect.Effect<void, HuntError>;
    readonly readRun: (runId: string) => Effect.Effect<{ run: HuntRun; directory: string; events: HuntEvent[] }, HuntError>;
    readonly appendEvent: (
      runId: string,
      type: string,
      state: RunState,
      data: Record<string, unknown>,
    ) => Effect.Effect<HuntEvent, HuntError>;
    readonly verifyRun: (runId: string) => Effect.Effect<{ valid: true; eventCount: number; artifactCount: number; lastEventHash: string }, HuntError>;
    readonly hashFile: (path: string) => Effect.Effect<Artifact, HuntError>;
  }
>() {}

export const LedgerServiceLive = Layer.succeed(
  LedgerService,
  LedgerService.of({
    initRun: (run) =>
      Effect.tryPromise({
        try: async () => {
          const directory = runDirectory(run.id);
          await withRunLock(directory, async () => {
            const unsignedEvent = {
              sequence: 1,
              timestamp: run.createdAt,
              type: "run_scoped",
              state: "SCOPED" as const,
              data: { scope: run.scope },
              previousHash: "GENESIS",
            };
            const initialEvent: HuntEvent = {
              ...unsignedEvent,
              hash: hashEvent(unsignedEvent),
            };

            const updatedRun: HuntRun = {
              ...run,
              lastEventHash: initialEvent.hash,
              eventCount: 1,
            };

            await atomicWrite(join(directory, "run.json"), `${JSON.stringify(updatedRun, null, 2)}\n`);
            await atomicWrite(join(directory, "events.jsonl"), `${JSON.stringify(initialEvent)}\n`);
          });
        },
        catch: (cause) => toHuntError("INIT_RUN_FAILED", cause),
      }),

    readRun: (runId) =>
      Effect.tryPromise({
        try: async () => {
          assertRunId(runId);
          const directory = runDirectory(runId);
          const rawRun = await readJson<HuntRun>(join(directory, "run.json"));
          if (rawRun.id !== runId || rawRun.version !== 1) {
            throw new HuntError("CORRUPT_RUN", "Run metadata does not match the requested id");
          }
          let content: string;
          try {
            content = await readFile(join(directory, "events.jsonl"), "utf8");
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") content = "";
            else throw error;
          }
          const events = content
            .split("\n")
            .filter(Boolean)
            .map((line, index) => {
              try {
                return JSON.parse(line) as HuntEvent;
              } catch (cause) {
                throw new HuntError("CORRUPT_LEDGER", `Invalid event JSON at line ${index + 1}`, { cause });
              }
            });
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
        },
        catch: (cause) => toHuntError("READ_RUN_FAILED", cause),
      }),

    appendEvent: (runId, type, state, data) =>
      Effect.tryPromise({
        try: async () => {
          assertRunId(runId);
          const directory = runDirectory(runId);
          return await withRunLock(directory, async () => {
            const rawRun = await readJson<HuntRun>(join(directory, "run.json"));
            let content = "";
            try {
              content = await readFile(join(directory, "events.jsonl"), "utf8");
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
            }
            const events = content.split("\n").filter(Boolean).map((line) => JSON.parse(line) as HuntEvent);
            verifyEventChain(events);
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
              ...rawRun,
              state,
              updatedAt: event.timestamp,
              eventCount: event.sequence,
              lastEventHash: event.hash,
            };

            await atomicWrite(join(directory, "run.json"), `${JSON.stringify(updatedRun, null, 2)}\n`);
            const eventLine = `${JSON.stringify(event)}\n`;
            await writeFile(join(directory, "events.jsonl"), eventLine, { flag: "a", mode: 0o600 });
            return event;
          });
        },
        catch: (cause) => toHuntError("APPEND_EVENT_FAILED", cause),
      }),

    verifyRun: (runId) =>
      Effect.tryPromise({
        try: async () => {
          assertRunId(runId);
          const directory = runDirectory(runId);
          let content = "";
          try {
            content = await readFile(join(directory, "events.jsonl"), "utf8");
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          const events = content.split("\n").filter(Boolean).map((line) => JSON.parse(line) as HuntEvent);
          verifyEventChain(events);

          const knownArtifacts = new Map<string, Artifact>();
          for (const event of events) {
            const artifacts = (event.data?.artifacts ?? []) as Artifact[];
            const evidence = (event.data?.evidence ?? []) as Artifact[];
            const report = event.data?.report as Artifact | undefined;
            const allArtifacts = [...artifacts, ...evidence, ...(report ? [report] : [])];
            for (const artifact of allArtifacts) {
              const previous = knownArtifacts.get(artifact.path);
              if (previous && (previous.sha256 !== artifact.sha256 || previous.size !== artifact.size)) {
                throw new HuntError("CORRUPT_ARTIFACT", `Conflicting artifact records: ${artifact.path}`);
              }
              knownArtifacts.set(artifact.path, artifact);
            }
          }

          for (const artifact of knownArtifacts.values()) {
            try {
              const fileContent = await readFile(artifact.path);
              if (sha256(fileContent) !== artifact.sha256) {
                throw new HuntError("CORRUPT_ARTIFACT", `Artifact checksum mismatch: ${artifact.path}`);
              }
            } catch (cause) {
              if (cause instanceof HuntError) throw cause;
              throw new HuntError("CORRUPT_ARTIFACT", `Missing artifact: ${artifact.path}`, { cause });
            }
          }

          return {
            valid: true as const,
            eventCount: events.length,
            artifactCount: knownArtifacts.size,
            lastEventHash: events.at(-1)?.hash ?? "GENESIS",
          };
        },
        catch: (cause) => toHuntError("VERIFY_FAILED", cause),
      }),

    hashFile: (path) =>
      Effect.tryPromise({
        try: async () => {
          const content = await readFile(path);
          return {
            path,
            sha256: sha256(content),
            size: content.length,
          };
        },
        catch: (cause) => toHuntError("HASH_FILE_FAILED", cause),
      }),
  }),
);
