import { Context, Effect, Layer } from "effect";
import { HuntError, toHuntError } from "../errors.js";

export interface ProtocolTarget {
  id: string;
  name: string;
  category: string;
  tvlUsd: number;
  tvlTier: "tier-1-above-1b" | "tier-2-100m-1b" | "tier-3-10m-100m" | "tier-4-1m-10m";
  bountyPlatform: "immunefi" | "cantina" | "code4rena" | "sherlock" | "self-hosted";
  bountyUrl: string;
  maxBountyUsd: number;
  chains: Array<{
    chainId: number;
    chainName: string;
    contracts: Array<{
      name: string;
      address: string;
      role: "core" | "oracle" | "vault" | "pool" | "adapter" | "bridge";
    }>;
  }>;
  websiteUrl?: string | undefined;
}

export interface AutoTargetSelection {
  target: ProtocolTarget;
  primaryChainId: number;
  chainName: string;
  primaryContract: {
    name: string;
    address: string;
    role: "core" | "oracle" | "vault" | "pool" | "adapter" | "bridge";
  };
}

export interface ReconQueryOptions {
  query?: string | undefined;
  chainId?: number | undefined;
  category?: string | undefined;
  minTvlUsd?: number | undefined;
  maxTvlUsd?: number | undefined;
  excludeTargetIds?: string[] | undefined;
}

const CHAIN_NAME_TO_ID: Record<string, number> = {
  ethereum: 1,
  arbitrum: 42161,
  base: 8453,
  bsc: 56,
  binance: 56,
  polygon: 137,
  sonic: 146,
  berachain: 80094,
  mantle: 5000,
  optimism: 10,
  "op mainnet": 10,
  avalanche: 43114,
  scroll: 534352,
  linea: 59144,
  blast: 81457,
  gnosis: 100,
  xdai: 100,
  fantom: 250,
  celo: 42220,
};

const ID_TO_CHAIN_NAME: Record<number, string> = {
  1: "Ethereum Mainnet",
  10: "Optimism",
  56: "BNB Smart Chain",
  100: "Gnosis Chain",
  137: "Polygon",
  146: "Sonic Mainnet",
  250: "Fantom",
  1101: "Polygon zkEVM",
  5000: "Mantle",
  8453: "Base",
  42161: "Arbitrum One",
  42220: "Celo",
  43114: "Avalanche",
  59144: "Linea",
  80094: "Berachain",
  81457: "Blast",
  534352: "Scroll",
};

let cachedLiveProtocols: ProtocolTarget[] | null = null;
let cacheExpiry = 0;

function parseAddressAndChain(rawAddress: string | null | undefined, chains: string[] | undefined): { address: string; chainId: number; chainName: string } | null {
  if (!rawAddress) return null;
  let address = rawAddress.trim();
  let chainId = 1;
  let chainName = "Ethereum Mainnet";

  if (address.includes(":")) {
    const parts = address.split(":");
    const prefix = parts[0]?.toLowerCase() ?? "";
    address = parts[1] ?? "";
    if (CHAIN_NAME_TO_ID[prefix]) {
      chainId = CHAIN_NAME_TO_ID[prefix]!;
      chainName = ID_TO_CHAIN_NAME[chainId] ?? parts[0]!;
    }
  } else if (chains && chains.length > 0) {
    for (const c of chains) {
      const lower = c.toLowerCase();
      if (CHAIN_NAME_TO_ID[lower]) {
        chainId = CHAIN_NAME_TO_ID[lower]!;
        chainName = ID_TO_CHAIN_NAME[chainId] ?? c;
        break;
      }
    }
  }

  if (!/^0x[a-fA-F0-9]{40}$/i.test(address)) return null;
  return { address, chainId, chainName };
}

function computeTvlTier(tvl: number): "tier-1-above-1b" | "tier-2-100m-1b" | "tier-3-10m-100m" | "tier-4-1m-10m" {
  if (tvl >= 1_000_000_000) return "tier-1-above-1b";
  if (tvl >= 100_000_000) return "tier-2-100m-1b";
  if (tvl >= 10_000_000) return "tier-3-10m-100m";
  return "tier-4-1m-10m";
}

export async function fetchLiveDefiProtocols(): Promise<ProtocolTarget[]> {
  const now = Date.now();
  if (cachedLiveProtocols && now < cacheExpiry) {
    return cachedLiveProtocols;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch("https://api.llama.fi/protocols", {
      signal: controller.signal,
      headers: { "User-Agent": "pi-web3-hunter/recon" },
    });
    clearTimeout(timeout);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as Array<{
      name?: string;
      slug?: string;
      category?: string;
      tvl?: number;
      chains?: string[];
      address?: string | null;
      url?: string;
    }>;

    const targets: ProtocolTarget[] = [];

    for (const p of data) {
      if (!p.name || typeof p.tvl !== "number" || p.tvl < 300_000) continue;
      if (p.category === "CEX" || p.category === "Chain") continue;

      const parsed = parseAddressAndChain(p.address, p.chains);
      if (!parsed) continue;

      const slug = p.slug || p.name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
      const tvl = Math.round(p.tvl);
      const estBounty = Math.min(2_500_000, Math.max(50_000, Math.round(tvl * 0.02)));

      targets.push({
        id: slug,
        name: p.name,
        category: p.category ?? "DeFi",
        tvlUsd: tvl,
        tvlTier: computeTvlTier(tvl),
        bountyPlatform: "immunefi",
        bountyUrl: `https://immunefi.com/bug-bounty/${slug}/`,
        maxBountyUsd: estBounty,
        ...(p.url ? { websiteUrl: p.url } : {}),
        chains: [
          {
            chainId: parsed.chainId,
            chainName: parsed.chainName,
            contracts: [
              {
                name: `${p.name.replace(/[^a-zA-Z0-9]/g, "")}Core`,
                address: parsed.address,
                role: "core",
              },
            ],
          },
        ],
      });
    }

    if (targets.length > 0) {
      cachedLiveProtocols = targets;
      cacheExpiry = now + 10 * 60 * 1000; // 10 minutes cache
      return targets;
    }
  } catch {
    // If online fetch fails, fallback to fallback list
  }

  return FALLBACK_CURATED_TARGETS;
}

export const FALLBACK_CURATED_TARGETS: ProtocolTarget[] = [
  {
    id: "aave-v3",
    name: "Aave V3",
    category: "Lending",
    tvlUsd: 17_000_000_000,
    tvlTier: "tier-1-above-1b",
    bountyPlatform: "immunefi",
    bountyUrl: "https://immunefi.com/bug-bounty/aave/",
    maxBountyUsd: 2_000_000,
    chains: [
      {
        chainId: 1,
        chainName: "Ethereum Mainnet",
        contracts: [
          { name: "PoolAddressesProvider", address: "0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e", role: "core" },
          { name: "Pool-Proxy", address: "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", role: "core" },
        ],
      },
    ],
  },
  {
    id: "uniswap-v3",
    name: "Uniswap V3",
    category: "Dexs",
    tvlUsd: 4_500_000_000,
    tvlTier: "tier-1-above-1b",
    bountyPlatform: "immunefi",
    bountyUrl: "https://immunefi.com/bug-bounty/uniswap/",
    maxBountyUsd: 3_000_000,
    chains: [
      {
        chainId: 1,
        chainName: "Ethereum Mainnet",
        contracts: [
          { name: "UniswapV3Factory", address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", role: "core" },
        ],
      },
    ],
  },
  {
    id: "morpho-blue",
    name: "Morpho Blue",
    category: "Lending",
    tvlUsd: 2_100_000_000,
    tvlTier: "tier-1-above-1b",
    bountyPlatform: "immunefi",
    bountyUrl: "https://immunefi.com/bug-bounty/morpho/",
    maxBountyUsd: 2_500_000,
    chains: [
      {
        chainId: 1,
        chainName: "Ethereum Mainnet",
        contracts: [
          { name: "MorphoBlue", address: "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb", role: "core" },
        ],
      },
    ],
  },
  {
    id: "aerodrome-v1",
    name: "Aerodrome Finance",
    category: "Dexs",
    tvlUsd: 260_000_000,
    tvlTier: "tier-2-100m-1b",
    bountyPlatform: "immunefi",
    bountyUrl: "https://immunefi.com/bug-bounty/aerodrome/",
    maxBountyUsd: 250_000,
    chains: [
      {
        chainId: 8453,
        chainName: "Base",
        contracts: [
          { name: "PoolFactory", address: "0x420DD381b31aEf6683db6B902084cB0FFECe40Da", role: "core" },
        ],
      },
    ],
  },
];

export const CURATED_MAINNET_TARGETS = FALLBACK_CURATED_TARGETS;

export class ReconService extends Context.Tag("ReconService")<
  ReconService,
  {
    readonly searchTargets: (options?: ReconQueryOptions) => Effect.Effect<ProtocolTarget[], HuntError>;
    readonly getTargetById: (id: string) => Effect.Effect<ProtocolTarget, HuntError>;
    readonly pickAutoTarget: (
      query?: string,
      preferredChainId?: number,
      excludeTargetIds?: string[],
    ) => Effect.Effect<AutoTargetSelection, HuntError>;
  }
>() {}

export const ReconServiceLive = Layer.succeed(
  ReconService,
  ReconService.of({
    searchTargets: (options) =>
      Effect.tryPromise({
        try: async () => {
          const allProtocols = await fetchLiveDefiProtocols();
          let results = allProtocols;

          if (!options) return results.slice(0, 50);

          if (options.excludeTargetIds && options.excludeTargetIds.length > 0) {
            const excludedLower = options.excludeTargetIds.map((id) => id.toLowerCase());
            results = results.filter(
              (t) => !excludedLower.includes(t.id.toLowerCase()) && !excludedLower.includes(t.name.toLowerCase()),
            );
          }

          if (options.chainId !== undefined) {
            results = results.filter((target) => target.chains.some((c) => c.chainId === options.chainId));
          }

          if (options.category) {
            const cat = options.category.toLowerCase();
            results = results.filter((target) => target.category.toLowerCase().includes(cat));
          }

          if (options.minTvlUsd !== undefined) {
            results = results.filter((target) => target.tvlUsd >= options.minTvlUsd!);
          }

          if (options.maxTvlUsd !== undefined) {
            results = results.filter((target) => target.tvlUsd <= options.maxTvlUsd!);
          }

          if (options.query) {
            const q = options.query.toLowerCase().trim();
            results = results.filter(
              (target) =>
                target.name.toLowerCase().includes(q) ||
                target.id.toLowerCase().includes(q) ||
                target.category.toLowerCase().includes(q) ||
                target.chains.some((c) =>
                  c.chainName.toLowerCase().includes(q) ||
                  c.contracts.some((k) => k.name.toLowerCase().includes(q) || k.address.toLowerCase().includes(q)),
                ),
            );
          }

          return results.slice(0, 50);
        },
        catch: (cause) => toHuntError("RECON_SEARCH_FAILED", cause),
      }),

    getTargetById: (id) =>
      Effect.gen(function* () {
        const allProtocols = yield* Effect.tryPromise({
          try: () => fetchLiveDefiProtocols(),
          catch: (cause) => toHuntError("RECON_GET_FAILED", cause),
        });
        const target = allProtocols.find(
          (t) => t.id.toLowerCase() === id.toLowerCase() || t.name.toLowerCase() === id.toLowerCase(),
        );
        if (!target) {
          return yield* Effect.fail(new HuntError("NOT_FOUND", `Mainnet protocol target '${id}' not found`));
        }
        return target;
      }),

    pickAutoTarget: (query, preferredChainId, excludeTargetIds) =>
      Effect.gen(function* () {
        const allProtocols = yield* Effect.tryPromise({
          try: () => fetchLiveDefiProtocols(),
          catch: (cause) => toHuntError("RECON_PICK_FAILED", cause),
        });

        let pool = allProtocols;

        if (excludeTargetIds && excludeTargetIds.length > 0) {
          const excludedLower = excludeTargetIds.map((id) => id.toLowerCase());
          pool = pool.filter(
            (t) => !excludedLower.includes(t.id.toLowerCase()) && !excludedLower.includes(t.name.toLowerCase()),
          );
        }

        let targetChain: number | undefined = preferredChainId;
        if (!targetChain && query) {
          const q = query.toLowerCase();
          if (q.includes("base")) targetChain = 8453;
          else if (q.includes("arb") || q.includes("arbitrum")) targetChain = 42161;
          else if (q.includes("eth") || q.includes("mainnet")) targetChain = 1;
          else if (q.includes("bsc") || q.includes("bnb")) targetChain = 56;
          else if (q.includes("sonic")) targetChain = 146;
          else if (q.includes("berachain") || q.includes("bera")) targetChain = 80094;
          else if (q.includes("mantle")) targetChain = 5000;
          else if (q.includes("polygon")) targetChain = 137;
        }

        let matched = pool;

        if (query) {
          const q = query.toLowerCase().trim();
          const filtered = pool.filter(
            (t) =>
              t.name.toLowerCase().includes(q) ||
              t.id.toLowerCase().includes(q) ||
              t.category.toLowerCase().includes(q) ||
              (targetChain !== undefined && t.chains.some((c) => c.chainId === targetChain)),
          );
          if (filtered.length > 0) {
            matched = filtered;
          }
        }

        if (targetChain !== undefined) {
          const onChain = matched.filter((t) => t.chains.some((c) => c.chainId === targetChain));
          if (onChain.length > 0) matched = onChain;
        }

        // Prioritize the "sweet spot" for vulnerabilities: active mainnet TVL ($1M - $100M)
        // High TVL means real assets & revenue; not being 5-year over-audited means realistic bug discovery chance.
        const sweetSpot = matched.filter((t) => t.tvlUsd >= 1_000_000 && t.tvlUsd <= 150_000_000);
        const candidates = sweetSpot.length > 0 ? sweetSpot : matched;

        if (candidates.length === 0) {
          if (allProtocols.length > 0) {
            candidates.push(allProtocols[0]!);
          } else {
            return yield* Effect.fail(
              new HuntError("ALL_TARGETS_EXHAUSTED", "No available dynamic mainnet targets found."),
            );
          }
        }

        const selectedTarget = candidates[0]!;
        const chainEntry =
          targetChain !== undefined
            ? selectedTarget.chains.find((c) => c.chainId === targetChain) ?? selectedTarget.chains[0]!
            : selectedTarget.chains[0]!;

        const primaryContract =
          chainEntry.contracts.find((k) => k.role === "core" || k.role === "vault" || k.role === "pool") ??
          chainEntry.contracts[0]!;

        return {
          target: selectedTarget,
          primaryChainId: chainEntry.chainId,
          chainName: chainEntry.chainName,
          primaryContract,
        };
      }),
  }),
);
