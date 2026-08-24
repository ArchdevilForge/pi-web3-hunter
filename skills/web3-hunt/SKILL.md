---
name: web3-hunt
description: Run an authorized Web3 bug-bounty hunt focusing on active Mainnet protocols, live DeFi TVL scouting, verified contract pulling, local-fork PoC validation, evidence capture, seven-gate triage, and report generation. Supports dynamic online research and continuous multi-target /hunt auto mode.
---

# Web3 Hunt (Dynamic Live Mainnet Scouting & Continuous Fork Verification)

The user already attested authorization when `/hunt` or `/hunt auto` created the run. Keep every action inside the run scope.

Prioritize **real, active Mainnet protocols with live TVL and on-chain revenue ($1M - $100M TVL sweet spot: actively deployed, real funds at risk, newer codebases with higher vulnerability probability)** over stale, 5-year over-audited contracts or zero-value testnets.

`RUN_ID` is supplied in the invocation. Start with `web3_hunt_status` and use that run ID in every Web3 Hunter tool call.

---

## ⚡ CONTINUOUS MULTI-TARGET AUTO-LOOP (`mode=auto` or `mode=loop`)

**Core Invariant**: The autonomous hunt **MUST NOT STOP** until at least **ONE valid, confirmed, non-falsifiable vulnerability with demonstrable economic impact** is proved on a local fork and confirmed through all 7 validation gates (`web3_record_finding`).

### ⚠️ CRITICAL: DO NOT STOP YOUR TURN BETWEEN TARGETS
In the Pi coding agent, **outputting conversational response text ends your turn and pauses the autonomous loop**.
Therefore, when an audited target yields **0 confirmed findings** (all hypotheses killed):
1. **DO NOT output conversational messages to the user**.
2. **DO NOT pause or end your turn**.
3. **IMMEDIATELY invoke `web3_auto_next_target`** (with `excludeTargetIds: ["<completed_target_id>", ...]`) as a tool call in the same or next turn to pull the next live Mainnet protocol.
4. Seamlessly switch to the newly scaffolded workspace (`./<target-id>-audit`), run scanners (`slither`/`aderyn`), map invariants, and execute fork PoCs.
5. Repeat tool calls continuously without stopping until a real vulnerability is confirmed!

---

## Standard Target Analysis Pipeline

### 1. Dynamic Reconnaissance & Workspace Verification

1. Use `web3_recon` or `web3_auto_next_target` to dynamically search live on-chain protocols by category (`dex`, `lending`, `yield`, `derivatives`, `liquid-staking`) or chain.
2. Verify contract source files in `src/` and the generated `test/ExploitPoC.t.sol`. (If missing, use `web3_pull_contract`).
3. Note target Chain ID and RPC endpoint for local fork tests.

### 2. Threat Model & Invariant Mapping

Inspect core value pools, vaults, oracles, routers, and permissionless entry points. Focus on high-value Mainnet vulnerability classes:
- **Price & Oracle Manipulation**: Flash loan skewing of spot AMMs, stale sequencer feeds, zero-price fallbacks, Uniswap TWAP manipulation.
- **Vault & Share Accounting**: First deposit inflation (ERC-4626), rounding drift in deposit/withdraw ratios, slippage bypass, donation attacks.
- **Cross-Contract & Reentrancy**: Read-only reentrancy across curve/balancer pools, callback hijacking in multicall/flash loans.
- **Access Control & Privileged Invariants**: Unprotected initialize/upgrade functions, signature replay across chains, permit frontrunning.

Completion: every permissionless value-moving entry point maps to guards, writes, external calls, and at least one financial invariant.

### 3. Hypotheses & Static Analysis

1. Run `web3_run_tool` with `slither` and `aderyn` on the target contracts.
2. Formulate concrete hypotheses. For each anomaly, state:
   - attacker prerequisites (capital, permissions);
   - exact transaction/call sequence;
   - violated invariant;
   - expected economic impact (drainable funds, frozen TVL);
   - cheapest falsifying experiment.

Record unresolved hypotheses as `candidate`. Record disproved hypotheses as `killed`.

> **陷阱直接 kill**：
> - `MasterChef/ vault` 的 `fee-on-transfer / deflationary` 记账膨胀（`user.amount += _amount` 未用 `balanceOf delta`），若 `add()/addPool()` 为 `onlyOwner` 且 PoC 用 `vm.prank(owner)` 加白攻击者 Token → `realisticAttacker=false, notKnownOrIntended=false` 直接记 `killed`（Sushi Fork 已知不支持 fee token）。仅当池已白名单且有真实 TVL、攻击者无特权即可触发时才算。
> - `ERC4626 首充膨胀`（`supply==0?assets:assets*supply/totalAssets` 无 virtual offset）：若 PoC 用 `VulnerableOZVault/MockSfrxVault` 现场部署 `supply=1, 1 wei + donation` 的空池模拟，而非 `0xac3E` 本体在 `fork block` 的真实 `totalSupply/totalAssets` 快照（含 `ZERO_SHARES` revert 与 7 天 `syncRewards` vesting），一律 `killed`。真洞需在真实 TVL 池上 `previewDeposit==0` 且 `deposit` 不 revert。

### 4. Mainnet Fork Validation & Scaffold PoC

1. Use `web3_scaffold_poc` to construct a verifiable Foundry Exploit test in `test/exploit/PoC_<id>.t.sol` using Mainnet fork state (`forge test --fork-url <RPC> -vvvv`).
2. Use `web3_run_tool` for allowlisted scanners (`forge-test`, `slither`, `aderyn`, `halmos`, `echidna`, `medusa`).
3. Direct chain writes, live transaction broadcasts, and private keys are strictly prohibited. All attacks must be reproduced deterministically on a local fork at a pinned block number.
4. Capture PoC output, traces, and state deltas. Run `web3_detached_audit` to independently confirm the 7 gates in a fresh detached subprocess — **detached auditor 会机械扫描证据文件，若含 `vm.prank(owner)` 加池或 fee-token 套路则自动驳回 `realisticAttacker/notKnownOrIntended`**。A finding becomes `confirmed` only when all seven fields passed to `web3_record_finding` are true:

1. `reproduced`
2. `impactInScope`
3. `rootCauseInScope`
4. `realisticAttacker`
5. `notKnownOrIntended`
6. `impactDemonstrated`
7. `pinnedAndRepeatable`

### 5. Triage Decision & Loop Continuation

- **If `confirmed > 0`**: Call `web3_build_report`, then `web3_verify_evidence`. Now you may output the final confirmed bounty report to the user!
- **If `confirmed == 0` (all hypotheses killed)**: In `mode=auto`, **DO NOT PRINT TEXT TO THE USER**. Immediately call `web3_auto_next_target` and continue the hunt without stopping!
