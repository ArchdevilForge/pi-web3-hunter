import { Context, Effect, Layer } from "effect";
import { mkdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { HuntError, toHuntError } from "../errors.js";

export interface ChainConfig {
  name: string;
  chainId: number;
  rpcUrls: string[];
  blockExplorerApi?: string;
  blockscoutDomain?: string;
  sourcifySupported: boolean;
}

export const KNOWN_CHAINS: Record<number, ChainConfig> = {
  1: {
    name: "Ethereum Mainnet",
    chainId: 1,
    rpcUrls: ["https://eth.llamarpc.com", "https://rpc.ankr.com/eth", "https://cloudflare-eth.com"],
    blockExplorerApi: "https://api.etherscan.io/api",
    blockscoutDomain: "eth.blockscout.com",
    sourcifySupported: true,
  },
  10: {
    name: "Optimism",
    chainId: 10,
    rpcUrls: ["https://mainnet.optimism.io", "https://optimism.llamarpc.com"],
    blockExplorerApi: "https://api-optimistic.etherscan.io/api",
    blockscoutDomain: "optimism.blockscout.com",
    sourcifySupported: true,
  },
  56: {
    name: "BNB Smart Chain",
    chainId: 56,
    rpcUrls: ["https://bsc-dataseed.binance.org", "https://bsc.llamarpc.com"],
    blockExplorerApi: "https://api.bscscan.com/api",
    blockscoutDomain: "bsc.blockscout.com",
    sourcifySupported: true,
  },
  100: {
    name: "Gnosis Chain",
    chainId: 100,
    rpcUrls: ["https://rpc.gnosischain.com", "https://gnosis.llamarpc.com"],
    blockExplorerApi: "https://api.gnosisscan.io/api",
    blockscoutDomain: "gnosis.blockscout.com",
    sourcifySupported: true,
  },
  137: {
    name: "Polygon",
    chainId: 137,
    rpcUrls: ["https://polygon-rpc.com", "https://polygon.llamarpc.com"],
    blockExplorerApi: "https://api.polygonscan.com/api",
    blockscoutDomain: "polygon.blockscout.com",
    sourcifySupported: true,
  },
  146: {
    name: "Sonic Mainnet",
    chainId: 146,
    rpcUrls: ["https://rpc.soniclabs.com"],
    blockExplorerApi: "https://api.sonicscan.org/api",
    blockscoutDomain: "sonic.blockscout.com",
    sourcifySupported: true,
  },
  250: {
    name: "Fantom Opera",
    chainId: 250,
    rpcUrls: ["https://rpc.ftm.tools", "https://fantom.llamarpc.com"],
    blockExplorerApi: "https://api.ftmscan.com/api",
    blockscoutDomain: "fantom.blockscout.com",
    sourcifySupported: true,
  },
  1101: {
    name: "Polygon zkEVM",
    chainId: 1101,
    rpcUrls: ["https://zkevm-rpc.com"],
    blockExplorerApi: "https://api-zkevm.polygonscan.com/api",
    blockscoutDomain: "zkevm.blockscout.com",
    sourcifySupported: true,
  },
  1329: {
    name: "Sei Network",
    chainId: 1329,
    rpcUrls: ["https://evm-rpc.sei-apis.com"],
    blockscoutDomain: "sei.blockscout.com",
    sourcifySupported: true,
  },
  5000: {
    name: "Mantle",
    chainId: 5000,
    rpcUrls: ["https://rpc.mantle.xyz", "https://mantle.llamarpc.com"],
    blockExplorerApi: "https://api.mantlescan.xyz/api",
    blockscoutDomain: "mantle.blockscout.com",
    sourcifySupported: true,
  },
  8453: {
    name: "Base",
    chainId: 8453,
    rpcUrls: ["https://mainnet.base.org", "https://base.llamarpc.com"],
    blockExplorerApi: "https://api.basescan.org/api",
    blockscoutDomain: "base.blockscout.com",
    sourcifySupported: true,
  },
  42161: {
    name: "Arbitrum One",
    chainId: 42161,
    rpcUrls: ["https://arb1.arbitrum.io/rpc", "https://arbitrum.llamarpc.com"],
    blockExplorerApi: "https://api.arbiscan.io/api",
    blockscoutDomain: "arbitrum.blockscout.com",
    sourcifySupported: true,
  },
  42220: {
    name: "Celo",
    chainId: 42220,
    rpcUrls: ["https://forno.celo.org"],
    blockExplorerApi: "https://api.celoscan.io/api",
    blockscoutDomain: "celo.blockscout.com",
    sourcifySupported: true,
  },
  43114: {
    name: "Avalanche C-Chain",
    chainId: 43114,
    rpcUrls: ["https://api.avax.network/ext/bc/C/rpc", "https://avalanche.llamarpc.com"],
    blockExplorerApi: "https://api.snowtrace.io/api",
    blockscoutDomain: "avax.blockscout.com",
    sourcifySupported: true,
  },
  59144: {
    name: "Linea",
    chainId: 59144,
    rpcUrls: ["https://rpc.linea.build"],
    blockExplorerApi: "https://api.lineascan.build/api",
    blockscoutDomain: "linea.blockscout.com",
    sourcifySupported: true,
  },
  80094: {
    name: "Berachain",
    chainId: 80094,
    rpcUrls: ["https://rpc.berachain.com"],
    blockscoutDomain: "berachain.blockscout.com",
    sourcifySupported: true,
  },
  81457: {
    name: "Blast",
    chainId: 81457,
    rpcUrls: ["https://rpc.blast.io"],
    blockExplorerApi: "https://api.blastscan.io/api",
    blockscoutDomain: "blast.blockscout.com",
    sourcifySupported: true,
  },
  534352: {
    name: "Scroll",
    chainId: 534352,
    rpcUrls: ["https://rpc.scroll.io"],
    blockExplorerApi: "https://api.scrollscan.com/api",
    blockscoutDomain: "scroll.blockscout.com",
    sourcifySupported: true,
  },
};

function parseJsonSources(sourceCode: string): Record<string, { content: string }> | undefined {
  let clean = sourceCode.trim();
  if (clean.startsWith("{{") && clean.endsWith("}}")) {
    clean = clean.slice(1, -1);
  }
  try {
    const parsed = JSON.parse(clean) as { sources?: Record<string, { content: string }> };
    if (parsed && parsed.sources && typeof parsed.sources === "object") {
      return parsed.sources;
    }
  } catch {
    // Not standard JSON
  }
  return undefined;
}

export async function fetchVerifiedSources(
  address: string,
  chainId: number,
  targetDir: string,
): Promise<{ sourceFound: boolean; path: string; files: string[]; contractName?: string }> {
  const normalized = address.toLowerCase();
  const config = KNOWN_CHAINS[chainId];
  const files: string[] = [];
  let contractName: string | undefined;

  const srcDir = join(targetDir, "src");

  // 1. Try Blockscout API v2
  if (config?.blockscoutDomain) {
    try {
      const res = await fetch(`https://${config.blockscoutDomain}/api/v2/smart-contracts/${normalized}`, {
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
          await mkdir(srcDir, { recursive: true });

          if (data.additional_sources && data.additional_sources.length > 0) {
            for (const item of data.additional_sources) {
              const fullPath = join(srcDir, item.file_path);
              await mkdir(join(fullPath, ".."), { recursive: true });
              await writeFile(fullPath, item.source_code, "utf8");
              files.push(fullPath);
            }
          } else if (data.source_code) {
            const jsonSources = parseJsonSources(data.source_code);
            if (jsonSources) {
              for (const [filePath, fileObj] of Object.entries(jsonSources)) {
                const fullPath = join(srcDir, filePath);
                await mkdir(join(fullPath, ".."), { recursive: true });
                await writeFile(fullPath, fileObj.content, "utf8");
                files.push(fullPath);
              }
            } else {
              const fileName = `${data.name ?? "Contract"}.sol`;
              const fullPath = join(srcDir, fileName);
              await writeFile(fullPath, data.source_code, "utf8");
              files.push(fullPath);
            }
          }

          if (files.length > 0) {
            await ensureFoundryScaffold(targetDir, chainId, address, contractName);
            return { sourceFound: true, path: targetDir, files, ...(contractName ? { contractName } : {}) };
          }
        }
      }
    } catch {
      // Fallback to next source
    }
  }

  // 2. Try Sourcify
  try {
    const res = await fetch(`https://sourcify.dev/server/files/any/${chainId}/${normalized}`, {
      headers: { "User-Agent": "pi-web3-hunter" },
    });
    if (res.ok) {
      const data = (await res.json()) as { files?: Array<{ name: string; path: string; content: string }> };
      if (data.files && data.files.length > 0) {
        await mkdir(srcDir, { recursive: true });
        for (const file of data.files) {
          if (file.name.endsWith(".sol") || file.path.endsWith(".sol")) {
            const relPath = file.path.startsWith("/") ? file.path.slice(1) : file.path || file.name;
            const fullPath = join(srcDir, relPath);
            await mkdir(join(fullPath, ".."), { recursive: true });
            await writeFile(fullPath, file.content, "utf8");
            files.push(fullPath);
          }
        }
        if (files.length > 0) {
          await ensureFoundryScaffold(targetDir, chainId, address, contractName);
          return { sourceFound: true, path: targetDir, files, ...(contractName ? { contractName } : {}) };
        }
      }
    }
  } catch {
    // Sourcify lookup failed
  }

  return { sourceFound: false, path: targetDir, files: [] };
}

async function ensureFoundryScaffold(
  targetDir: string,
  chainId: number,
  contractAddress: string,
  contractName?: string,
): Promise<void> {
  const foundryTomlPath = join(targetDir, "foundry.toml");
  try {
    await stat(foundryTomlPath);
  } catch {
    await writeFile(
      foundryTomlPath,
      `[profile.default]\nsrc = "src"\nout = "out"\ntest = "test"\nlibs = ["lib"]\neth_rpc_url = "${KNOWN_CHAINS[chainId]?.rpcUrls[0] ?? "http://127.0.0.1:8545"}"\n`,
      "utf8",
    );
  }

  const testDir = join(targetDir, "test");
  await mkdir(testDir, { recursive: true });
  const pocFile = join(testDir, "ExploitPoC.t.sol");
  try {
    await stat(pocFile);
  } catch {
    const cName = contractName ?? "TargetContract";
    const template = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface ITarget {
    // Fill in target contract interface functions
}

/**
 * @title Mainnet Fork Exploit PoC
 * @notice Target: ${contractAddress} on Chain ID: ${chainId} (${KNOWN_CHAINS[chainId]?.name ?? "Unknown"})
 * @dev Run with: forge test --fork-url <RPC_URL> -vvvv
 */
contract ExploitPoCTest is Test {
    address constant TARGET = ${contractAddress};
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Label addresses for clear trace output
        vm.label(TARGET, "${cName}");
        vm.label(attacker, "Attacker");
    }

    function testExploit() public {
        vm.startPrank(attacker);

        // 1. Initial State Check
        // 2. Perform Attack Simulation (e.g. Flashloan / Reentrancy / Oracle Arbitrage)
        // 3. Assert Invariant Violation or Financial Impact

        vm.stopPrank();
    }
}
`;
    await writeFile(pocFile, template, "utf8");
  }
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
