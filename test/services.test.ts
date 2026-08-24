import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import {
  KNOWN_CHAINS,
  MultiChainService,
  MultiChainServiceLive,
} from "../src/services/MultiChainService.js";
import { generatePoCTemplate, PoCService, PoCServiceLive } from "../src/services/PoCService.js";
import { DetachedAuditorService, DetachedAuditorServiceLive } from "../src/services/DetachedAuditorService.js";
import { ScannerService, ScannerServiceLive } from "../src/services/ScannerService.js";
import { FindingInput, HuntRun } from "../src/schema.js";

test("MultiChainService resolves public RPCs and configurations for known chains", async () => {
  const effect = Effect.gen(function* () {
    const service = yield* MultiChainService;
    const rpc1 = yield* service.getRpcUrl(1);
    assert.ok(rpc1.startsWith("http"));

    const configArbitrum = yield* service.getChainConfig(42161);
    assert.equal(configArbitrum.name, "Arbitrum One");
    assert.equal(configArbitrum.chainId, 42161);

    const configBase = yield* service.getChainConfig(8453);
    assert.equal(configBase.name, "Base");
  }).pipe(Effect.provide(MultiChainServiceLive));

  await Effect.runPromise(effect);
});

test("PoCService validates exploit source and detects forbidden cheatcodes", async () => {
  const effect = Effect.gen(function* () {
    const poc = yield* PoCService;

    const validTemplate = generatePoCTemplate({
      findingTitle: "Flashloan Reentrancy",
      targetContract: "0x1234567890123456789012345678901234567890",
      chainId: 1,
      forkBlock: 19000000,
    });
    assert.match(validTemplate, /contract ExploitPoCTest is Test/);
    assert.match(validTemplate, /function testExploit/);

    const validCheck = yield* poc.validatePoCSource(validTemplate);
    assert.equal(validCheck.valid, true);

    const cheatingPoC = `
      contract CheatTest {
        function testExploit() public {
          vm.store(address(0x1), bytes32(0), bytes32(uint256(100)));
        }
      }
    `;
    const cheatCheck = yield* poc.validatePoCSource(cheatingPoC);
    assert.equal(cheatCheck.valid, false);
    assert.match(cheatCheck.reasons[0] ?? "", /Forbidden cheatcode `vm\.store`/);

    const ownerPrankPoC = `
      contract CheatTest {
        function testExploit() public {
          address owner = IMasterChef(MC).owner();
          vm.prank(owner);
          IMasterChef(MC).add(100, address(feeToken), false);
        }
      }
    `;
    const ownerCheck = yield* poc.validatePoCSource(ownerPrankPoC);
    assert.equal(ownerCheck.valid, false);
    assert.match(ownerCheck.reasons[0] ?? "", /Privileged prank/);
  }).pipe(Effect.provide(PoCServiceLive));

  await Effect.runPromise(effect);
});

test("DetachedAuditorService verifies 7 gates independently", async () => {
  // Prepare fee-token owner-prank evidence file for gate test
  const dir = join(tmpdir(), "pi-hunter-test-" + Date.now());
  await mkdir(dir, { recursive: true });
  const pocPath = join(dir, "poc.sol");
  await writeFile(pocPath, "contract P { function testExploit() public { address owner = IMasterChef(MC).owner(); vm.prank(owner); IMasterChef(MC).add(100, address(feeToken), false); } } FeeToken", "utf8");

  const auditLayer = DetachedAuditorServiceLive.pipe(
    Layer.provide(ScannerServiceLive),
    Layer.provide(PoCServiceLive),
  );

  const mockRun: HuntRun = {
    version: 1,
    id: "run-20260823t120000z-12345678",
    state: "ANALYZING",
    scope: {
      kind: "repository",
      target: "/tmp/mock",
      targetRoot: "/tmp/mock",
      program: "test-bounty",
      authorization: "user-attested",
      createdAt: new Date().toISOString(),
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    eventCount: 1,
    lastEventHash: "GENESIS",
  };

  const passingFinding: FindingInput = {
    title: "Arbitrary Vault Drain",
    severity: "critical",
    status: "confirmed",
    rootCause: "Unchecked deposit ratio during withdrawal.",
    impact: "Total vault insolvency.",
    reproduction: "Run forge test against fork block.",
    gates: {
      reproduced: true,
      impactInScope: true,
      rootCauseInScope: true,
      realisticAttacker: true,
      notKnownOrIntended: true,
      impactDemonstrated: true,
      pinnedAndRepeatable: true,
    },
    evidencePaths: [],
  };

  const failingFinding: FindingInput = {
    ...passingFinding,
    gates: {
      ...passingFinding.gates,
      reproduced: false,
    },
  };

  const feeFindingWithFile: FindingInput = {
    ...passingFinding,
    title: "MasterChef - Fee-on-Transfer Accounting Inflation",
    evidencePaths: [pocPath],
  };

  const effect = Effect.gen(function* () {
    const auditor = yield* DetachedAuditorService;
    const passResult = yield* auditor.auditFinding(mockRun, passingFinding);
    assert.equal(passResult.approved, true);

    const failResult = yield* auditor.auditFinding(mockRun, failingFinding);
    assert.equal(failResult.approved, false);
    assert.match(failResult.reason ?? "", /reproduced/);

    const feeResult = yield* auditor.auditFinding(mockRun, feeFindingWithFile);
    assert.equal(feeResult.approved, false);
    assert.match(feeResult.reason ?? "", /realisticAttacker/);
    assert.equal(feeResult.gates.realisticAttacker, false);
    assert.equal(feeResult.gates.notKnownOrIntended, false);
  }).pipe(Effect.provide(auditLayer));

  await Effect.runPromise(effect);
  await rm(dir, { recursive: true, force: true });
});

import { ReconService, ReconServiceLive, CURATED_MAINNET_TARGETS } from "../src/services/ReconService.js";

test("MultiChainService resolves expanded mainnet chains like Sonic, Berachain, Mantle", async () => {
  const effect = Effect.gen(function* () {
    const service = yield* MultiChainService;

    const configSonic = yield* service.getChainConfig(146);
    assert.equal(configSonic.name, "Sonic Mainnet");

    const configBera = yield* service.getChainConfig(80094);
    assert.equal(configBera.name, "Berachain");

    const configMantle = yield* service.getChainConfig(5000);
    assert.equal(configMantle.name, "Mantle");
  }).pipe(Effect.provide(MultiChainServiceLive));

  await Effect.runPromise(effect);
});

test("ReconService filters and retrieves live mainnet targets", async () => {
  const effect = Effect.gen(function* () {
    const recon = yield* ReconService;

    const all = yield* recon.searchTargets();
    assert.ok(all.length >= 4);

    const aave = yield* recon.searchTargets({ query: "aave" });
    assert.ok(aave.length >= 1);
    assert.match(aave[0]?.name ?? "", /aave/i);

    const baseTargets = yield* recon.searchTargets({ chainId: 8453 });
    assert.ok(baseTargets.length >= 1);

    const target = yield* recon.getTargetById(all[0]!.id);
    assert.equal(target.id, all[0]!.id);
  }).pipe(Effect.provide(ReconServiceLive));

  await Effect.runPromise(effect);
});

test("ReconService.pickAutoTarget selects dynamic sweet-spot target, chain, and core contract", async () => {
  const effect = Effect.gen(function* () {
    const recon = yield* ReconService;

    const defaultPick = yield* recon.pickAutoTarget();
    assert.ok(defaultPick.target.id);
    assert.ok(defaultPick.primaryChainId > 0);
    assert.ok(defaultPick.primaryContract.address.startsWith("0x"));

    const dexPick = yield* recon.pickAutoTarget("dex");
    assert.ok(dexPick.target.name);

    const basePick = yield* recon.pickAutoTarget("base");
    assert.equal(basePick.primaryChainId, 8453);

    // Test excludeTargetIds
    const nextPick = yield* recon.pickAutoTarget(undefined, undefined, [defaultPick.target.id]);
    assert.notEqual(nextPick.target.id, defaultPick.target.id);
  }).pipe(Effect.provide(ReconServiceLive));

  await Effect.runPromise(effect);
});

