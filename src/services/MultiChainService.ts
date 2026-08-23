import { Context, Effect, Layer } from "effect";
import { mkdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { HuntError, toHuntError } from "../errors.js";

export interface ChainConfig {
  name: string;
  chainId: number;
  rpcUrls: string[];
  blockExplorerApi?: string;
  sourcifySupported: boolean;
}

export const KNOWN_CHAINS: Record<number, ChainConfig> = {
  1: {
    name: "Ethereum Mainnet",
    chainId: 1,
    rpcUrls: ["https://eth.llamarpc.com", "https://rpc.ankr.com/eth", "https://cloudflare-eth.com"],
    blockExplorerApi: "https://api.etherscan.io/api",
    sourcifySupported: true,
  },
  10: {
    name: "Optimism",
    chainId: 10,
    rpcUrls: ["https://mainnet.optimism.io", "https://optimism.llamarpc.com"],
    blockExplorerApi: "https://api-optimistic.etherscan.io/api",
    sourcifySupported: true,
  },
  56: {
    name: "BNB Smart Chain",
    chainId: 56,
    rpcUrls: ["https://bsc-dataseed.binance.org", "https://bsc.llamarpc.com"],
    blockExplorerApi: "https://api.bscscan.com/api",
    sourcifySupported: true,
  },
  137: {
    name: "Polygon",
    chainId: 137,
    rpcUrls: ["https://polygon-rpc.com", "https://polygon.llamarpc.com"],
    blockExplorerApi: "https://api.polygonscan.com/api",
    sourcifySupported: true,
  },
  8453: {
    name: "Base",
    chainId: 8453,
    rpcUrls: ["https://mainnet.base.org", "https://base.llamarpc.com"],
    blockExplorerApi: "https://api.basescan.org/api",
    sourcifySupported: true,
  },
  42161: {
    name: "Arbitrum One",
    chainId: 42161,
    rpcUrls: ["https://arb1.arbitrum.io/rpc", "https://arbitrum.llamarpc.com"],
    blockExplorerApi: "https://api.arbiscan.io/api",
    sourcifySupported: true,
  },
  43114: {
    name: "Avalanche C-Chain",
    chainId: 43114,
    rpcUrls: ["https://api.avax.network/ext/bc/C/rpc"],
    blockExplorerApi: "https://api.snowtrace.io/api",
    sourcifySupported: true,
  },
  59144: {
    name: "Linea",
    chainId: 59144,
    rpcUrls: ["https://rpc.linea.build"],
    blockExplorerApi: "https://api.lineascan.build/api",
    sourcifySupported: true,
  },
  534352: {
    name: "Scroll",
    chainId: 534352,
    rpcUrls: ["https://rpc.scroll.io"],
    blockExplorerApi: "https://api.scrollscan.com/api",
    sourcifySupported: true,
  },
};

async function fetchVerifiedSources(
  address: string,
  chainId: number,
  targetDir: string,
): Promise<{ sourceFound: boolean; path: string; files: string[]; contractName?: string }> {
  const normalized = address.toLowerCase();
  const domainMap: Record<number, string> = {
    1: "eth.blockscout.com",
    10: "optimism.blockscout.com",
    56: "bsc.blockscout.com",
    137: "polygon.blockscout.com",
    8453: "base.blockscout.com",
    42161: "arbitrum.blockscout.com",
    59144: "linea.blockscout.com",
    534352: "scroll.blockscout.com",
  };

  const domain = domainMap[chainId];
  const files: string[] = [];
  let contractName: string | undefined;

  if (domain) {
    try {
      const res = await fetch(`https://${domain}/api/v2/smart-contracts/${normalized}`, {
        headers: { "User-Agent": "pi-web3-hunter" },
      });
      if (res.ok) {
        const data = (await res.json()) as {
          is_verified?: boolean;
          name?: string;
          source_code?: string;
          additional_sources?: Array<{ file_path: string; source_code: string }>;
        };
        if (data.is_verified) {
          contractName = data.name;
          const srcDir = join(targetDir, "src");
          await mkdir(srcDir, { recursive: true });

          if (data.additional_sources && data.additional_sources.length > 0) {
            for (const item of data.additional_sources) {
              const fullPath = join(srcDir, item.file_path);
              await mkdir(join(fullPath, ".."), { recursive: true });
              await writeFile(fullPath, item.source_code, "utf8");
              files.push(fullPath);
            }
          } else if (data.source_code) {
            const fileName = `${data.name ?? "Contract"}.sol`;
            const fullPath = join(srcDir, fileName);
            await writeFile(fullPath, data.source_code, "utf8");
            files.push(fullPath);
          }

          // Generate foundry.toml scaffold if not present
          const foundryTomlPath = join(targetDir, "foundry.toml");
          try {
            await stat(foundryTomlPath);
          } catch {
            await writeFile(foundryTomlPath, `[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\n`, "utf8");
          }

          return { sourceFound: true, path: targetDir, files, ...(contractName ? { contractName } : {}) };
        }
      }
    } catch {
      // Fallback to Sourcify
    }
  }

  // Fallback to Sourcify
  try {
    const res = await fetch(`https://sourcify.dev/server/files/any/${chainId}/${normalized}`, {
      headers: { "User-Agent": "pi-web3-hunter" },
    });
    if (res.ok) {
      const data = (await res.json()) as { files?: Array<{ name: string; path: string; content: string }> };
      if (data.files && data.files.length > 0) {
        const srcDir = join(targetDir, "src");
        await mkdir(srcDir, { recursive: true });
        for (const file of data.files) {
          if (file.name.endsWith(".sol")) {
            const fullPath = join(srcDir, file.name);
            await mkdir(join(fullPath, ".."), { recursive: true });
            await writeFile(fullPath, file.content, "utf8");
            files.push(fullPath);
          }
        }
        if (files.length > 0) {
          return { sourceFound: true, path: targetDir, files };
        }
      }
    }
  } catch {
    // Sourcify lookup failed
  }

  return { sourceFound: false, path: targetDir, files: [] };
}

export class MultiChainService extends Context.Tag("MultiChainService")<
  MultiChainService,
  {
    readonly getRpcUrl: (chainId?: number) => Effect.Effect<string, HuntError>;
    readonly getChainConfig: (chainId: number) => Effect.Effect<ChainConfig, HuntError>;
    readonly resolveContractSource: (
      address: string,
      chainId: number,
      targetDir: string,
    ) => Effect.Effect<{ sourceFound: boolean; path: string; files: string[]; contractName?: string | undefined }, HuntError>;
  }
>() {}

export const MultiChainServiceLive = Layer.succeed(
  MultiChainService,
  MultiChainService.of({
    getRpcUrl: (chainId) =>
      Effect.sync(() => {
        const envRpc = process.env.WEB3_HUNTER_RPC_URL || process.env.ETH_RPC_URL;
        if (envRpc) return envRpc;
        if (chainId && KNOWN_CHAINS[chainId]) {
          const config = KNOWN_CHAINS[chainId];
          return config.rpcUrls[0] ?? "http://127.0.0.1:8545";
        }
        return "http://127.0.0.1:8545";
      }),

    getChainConfig: (chainId) =>
      Effect.gen(function* () {
        const config = KNOWN_CHAINS[chainId];
        if (!config) {
          return yield* Effect.fail(
            new HuntError("UNSUPPORTED_CHAIN", `Chain ID ${chainId} is not in known chain directory`),
          );
        }
        return config;
      }),

    resolveContractSource: (address, chainId, targetDir) =>
      Effect.tryPromise({
        try: async () => {
          if (!/^0x[a-fA-F0-9]{40}$/i.test(address)) {
            throw new HuntError("INVALID_ADDRESS", `Invalid EVM contract address: ${address}`);
          }
          return await fetchVerifiedSources(address, chainId, targetDir);
        },
        catch: (cause) => toHuntError("CONTRACT_RESOLVE_FAILED", cause),
      }),
  }),
);
