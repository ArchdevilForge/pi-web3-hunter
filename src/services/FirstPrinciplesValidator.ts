// First Principles Validator — 5 atoms that define a real bug
// Atom = necessary condition. One fails => killed. No LLM trust.
import { readFile } from "node:fs/promises";

export interface FiveAtomResult {
  scope: { pass: boolean; reason?: string };
  permissionless: { pass: boolean; reason?: string };
  state: { pass: boolean; reason?: string };
  economic: { pass: boolean; reason?: string };
  novelty: { pass: boolean; reason?: string };
  allPass: boolean;
  reasons: string[];
}

// Known-issue DB — SCSVS C4.12 / OZ / Yearn / Sushi
const KNOWN_ISSUES: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /fee.*transfer|deflationary/i, reason: "Sushi MasterChef fee-on-transfer: documented unsupported (add() onlyOwner + prank owner)" },
  { pattern: /VulnerableVault|VulnerableOZVault|MockSfrxVault.*supply.*1|first deposit inflation/i, reason: "ERC4626 first-deposit inflation on mock empty vault (supply=1) — real vault has large TVL, ZERO_SHARES, 7-day vesting" },
  { pattern: /yVault.*donation|donation.*pricePerShare|yVault.*balance\(\)/i, reason: "Yearn yVault donation griefing on large TVL — 38% share dilution but 1 wei loss at 10k size, not theft" },
  { pattern: /sfrxETH.*Mock|MockSfrxVault/i, reason: "sfrxETH mock not real fork state" },
];

const REAL_CONTRACTS: Record<string, RegExp> = {
  sfrxETH: /0xac3E018457B222d93114458476f3E3416Abbe38F/i,
  yVault: /0xB17640796e4c27a39AF51887aff3F8DC0daF9567/i,
  stakeDAO: /Stake DAO|stake-dao/i,
};

export function checkScope(evidenceText: string, title: string): { pass: boolean; reason?: string } {
  const claimsSfrx = /sfrxETH|0xac3E/i.test(title + evidenceText);
  const hasRealSfrx = REAL_CONTRACTS.sfrxETH!.test(evidenceText);
  const hasMockSfrx = /MockSfrxVault/.test(evidenceText);
  if (claimsSfrx && hasMockSfrx && !hasRealSfrx) {
    return { pass: false, reason: "rootCauseInScope: claims sfrxETH but PoC is MockSfrxVault, not real 0xac3E fork state" };
  }
  const claimsYVault = /yVault|sd3Crv|0xB176/i.test(title + evidenceText);
  const hasRealYVault = REAL_CONTRACTS.yVault!.test(evidenceText);
  const hasMockYVault = /VulnerableVault|VulnerableOZVault/.test(evidenceText) && !hasRealYVault;
  if (claimsYVault && hasMockYVault) {
    return { pass: false, reason: "rootCauseInScope: claims yVault but PoC is mock VulnerableOZVault" };
  }
  return { pass: true };
}

export function checkPermissionless(evidenceText: string): { pass: boolean; reason?: string } {
  const pranksOwner = /vm\.(startPrank|prank)\s*\(\s*owner\b/.test(evidenceText) || /vm\.(startPrank|prank)\s*\([^)]*\.owner\(\)/.test(evidenceText);
  const createsPool = /\.add\s*\(/.test(evidenceText) || /\.add\s*\([^)]*FeeToken/.test(evidenceText);
  if (pranksOwner && createsPool) {
    return { pass: false, reason: "realisticAttacker: pranks owner to add pool (add() is onlyOwner) — permissionless fails" };
  }
  if (pranksOwner) {
    return { pass: false, reason: "realisticAttacker: pranks owner/admin — not permissionless" };
  }
  return { pass: true };
}

export function checkState(evidenceText: string, title: string): { pass: boolean; reason?: string } {
  const hasFork = /vm\.createSelectFork|fork-block|fork-url/i.test(evidenceText);
  const isInflation = /First Deposit Inflation|ERC4626.*Inflation|Donation/i.test(title) || /supply\s*==\s*0\s*\?\s*assets/.test(evidenceText);
  const isMockEmpty = (/VulnerableVault|VulnerableOZVault/.test(evidenceText) && /supply\s*==\s*0\s*\?\s*assets/.test(evidenceText)) || /MockSfrxVault/.test(evidenceText) || /VulnerableVault/.test(evidenceText);
  const hasZeroSharesRevert = /ZERO_SHARES/.test(evidenceText);
  if (isInflation && isMockEmpty && !hasFork) {
    return { pass: false, reason: "state: ERC4626 inflation on mock empty vault without real fork (supply=1) — need real totalSupply/totalAssets snapshot" };
  }
  if (hasZeroSharesRevert && /victim.*0\s*shares/.test(evidenceText)) {
    return { pass: false, reason: "state: ZERO_SHARES revert would block 0-share victim deposit — not reproducible on real vault" };
  }
  return { pass: true };
}

export function checkEconomic(evidenceText: string, title: string): { pass: boolean; reason?: string } {
  // Parse profit/loss logs: attackerWithdrawn, victimWithdrawn, attacker profit, victim loss
  const mProfit = evidenceText.match(/attacker.*profit[^0-9]*([0-9]{10,})/i) || evidenceText.match(/profit[^0-9]*([0-9]{15,})/i);
  const mVictimLoss = evidenceText.match(/victim.*loss[^0-9]*([0-9]+)/i);
  const mVictimShares = evidenceText.match(/victimShares[^0-9]*([0-9]+)/i);
  const mDonation = evidenceText.match(/donation[^0-9]*([0-9]{10,})/i) || evidenceText.match(/donat[^0-9]*([0-9]{15,})/i);
  const isYVaultDonation = /yVault.*Donation|donation.*price/i.test(title + evidenceText);
  const isInflation = /Inflation|ERC4626/.test(title);

  // yVault: 38% dilution but 1 wei loss -> economic fails for Medium
  if (isYVaultDonation) {
    const victimLoss = mVictimLoss && mVictimLoss[1] ? BigInt(mVictimLoss[1]!) : null;
    // If victim loss is 1 wei at 10k size, not economic
    if (victimLoss !== null && victimLoss === 1n) {
      return { pass: false, reason: "economic: victim loss 1 wei at 10k deposit (38% share dilution but price compensates) — griefing, not theft; need dust 0-share with net profit > donation" };
    }
    const donation = mDonation && mDonation[1] ? BigInt(mDonation[1]!) : 50000n * 10n ** 18n;
    const profit = mProfit && mProfit[1] ? BigInt(mProfit[1]!) : null;
    if (profit !== null && donation !== null && profit < donation) {
      return { pass: false, reason: "economic: donation 50k > attacker withdraw 160k net loss (flash loan not repayable) — not profitable" };
    }
  }
  if (isInflation) {
    if (mProfit && mProfit[1] && BigInt(mProfit[1]!) === 0n) {
      return { pass: false, reason: "economic: profit 0 — not demonstrated" };
    }
  }
  return { pass: true };
}

export function checkNovelty(evidenceText: string, title: string): { pass: boolean; reason?: string } {
  const hay = title + "\n" + evidenceText;
  for (const k of KNOWN_ISSUES) {
    if (k.pattern.test(hay)) {
      // Need to ensure it's not just mention but actual exploit pattern
      const hasRealPattern = /FeeToken|MockSfrxVault|VulnerableVault|VulnerableOZVault|yVault.*donation/.test(evidenceText);
      if (hasRealPattern) {
        return { pass: false, reason: `notKnownOrIntended: known issue — ${k.reason}` };
      }
    }
  }
  return { pass: true };
}

export async function validateFiveAtoms(evidencePaths: string[], title: string): Promise<FiveAtomResult> {
  let evidenceText = "";
  for (const p of evidencePaths) {
    try {
      evidenceText += "\n" + (await readFile(p, "utf8"));
    } catch {}
  }
  const scope = checkScope(evidenceText, title);
  const permissionless = checkPermissionless(evidenceText);
  const state = checkState(evidenceText, title);
  const economic = checkEconomic(evidenceText, title);
  const novelty = checkNovelty(evidenceText, title);
  const reasons: string[] = [];
  if (!scope.pass) reasons.push(scope.reason!);
  if (!permissionless.pass) reasons.push(permissionless.reason!);
  if (!state.pass) reasons.push(state.reason!);
  if (!economic.pass) reasons.push(economic.reason!);
  if (!novelty.pass) reasons.push(novelty.reason!);
  return {
    scope,
    permissionless,
    state,
    economic,
    novelty,
    allPass: reasons.length === 0,
    reasons,
  };
}
