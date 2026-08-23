import { Context, Effect, Layer, Scope } from "effect";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { HuntError, toHuntError } from "../errors.js";

export interface AnvilInstance {
  readonly pid: number;
  readonly port: number;
  readonly rpcUrl: string;
  readonly chainId: number;
  readonly forkBlockNumber?: number | undefined;
  readonly process: ChildProcess;
}

function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        const port = address.port;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error("Unable to obtain free port")));
      }
    });
  });
}

function waitForAnvilReady(port: number, timeoutMs = 15_000): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:${port}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 }),
        });
        if (res.ok) {
          resolve();
          return;
        }
      } catch {
        // Not ready yet
      }
      if (Date.now() - start > timeoutMs) {
        reject(new HuntError("ANVIL_TIMEOUT", `Anvil did not become ready within ${timeoutMs}ms on port ${port}`));
        return;
      }
      setTimeout(check, 200);
    };
    check();
  });
}

export class ForkService extends Context.Tag("ForkService")<
  ForkService,
  {
    readonly startFork: (options: {
      rpcUrl: string;
      chainId?: number | undefined;
      forkBlockNumber?: number | undefined;
      silent?: boolean | undefined;
    }) => Effect.Effect<AnvilInstance, HuntError, Scope.Scope>;
  }
>() {}

export const ForkServiceLive = Layer.succeed(
  ForkService,
  ForkService.of({
    startFork: (options) =>
      Effect.acquireRelease(
        Effect.gen(function* () {
          const port = yield* Effect.tryPromise({
            try: () => findFreePort(),
            catch: (cause) => toHuntError("PORT_ALLOCATION_FAILED", cause),
          });

          const args = ["--port", String(port), "--fork-url", options.rpcUrl];
          if (options.chainId) args.push("--chain-id", String(options.chainId));
          if (options.forkBlockNumber !== undefined) {
            args.push("--fork-block-number", String(options.forkBlockNumber));
          }
          if (options.silent) args.push("--silent");

          const child = spawn("anvil", args, {
            detached: process.platform !== "win32",
            stdio: ["ignore", "pipe", "pipe"],
          });

          if (!child.pid) {
            return yield* Effect.fail(new HuntError("SPAWN_FAILED", "Failed to spawn anvil child process"));
          }

          yield* Effect.tryPromise({
            try: () => waitForAnvilReady(port),
            catch: (cause) => {
              if (child.pid && !child.killed) {
                try {
                  process.kill(-child.pid, "SIGKILL");
                } catch {
                  child.kill("SIGKILL");
                }
              }
              return toHuntError("ANVIL_START_FAILED", cause);
            },
          });

          const instance: AnvilInstance = {
            pid: child.pid,
            port,
            rpcUrl: `http://127.0.0.1:${port}`,
            chainId: options.chainId ?? 31337,
            ...(options.forkBlockNumber !== undefined ? { forkBlockNumber: options.forkBlockNumber } : {}),
            process: child,
          };
          return instance;
        }),
        (instance) =>
          Effect.sync(() => {
            if (instance.process.pid && !instance.process.killed) {
              try {
                if (process.platform === "win32") instance.process.kill("SIGKILL");
                else process.kill(-instance.process.pid, "SIGKILL");
              } catch {
                instance.process.kill("SIGKILL");
              }
            }
          }),
      ),
  }),
);
