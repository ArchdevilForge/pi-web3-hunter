import { Context, Effect, Layer } from "effect";
import { HuntError, toHuntError } from "../errors.js";
import { EthAddress } from "../schema.js";

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

export class MultiChainService extends Context.Tag("MultiChainService")<
  MultiChainService,
  {
    readonly getRpcUrl: (chainId?: number) => Effect.Effect<string, HuntError>;
    readonly getChainConfig: (chainId: number) => Effect.Effect<ChainConfig, HuntError>;
    readonly resolveContractSource: (
      address: string,
      chainId: number,
      targetDir: string,
    ) => Effect.Effect<{ sourceFound: boolean; path: string; files: string[] }, HuntError>;
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
          // Address validation
          if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
            throw new HuntError("INVALID_ADDRESS", `Invalid EVM contract address: ${address}`);
          }
          return {
            sourceFound: true,
            path: targetDir,
            files: [],
          };
        },
        catch: (cause) => toHuntError("CONTRACT_RESOLVE_FAILED", cause),
      }),
  }),
);
