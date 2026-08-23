import assert from "node:assert/strict";
import test from "node:test";
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
  }).pipe(Effect.provide(PoCServiceLive));

  await Effect.runPromise(effect);
});

test("DetachedAuditorService verifies 7 gates independently", async () => {
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

  const effect = Effect.gen(function* () {
    const auditor = yield* DetachedAuditorService;
    const passResult = yield* auditor.auditFinding(mockRun, passingFinding);
    assert.equal(passResult.approved, true);

    const failResult = yield* auditor.auditFinding(mockRun, failingFinding);
    assert.equal(failResult.approved, false);
    assert.match(failResult.reason ?? "", /reproduced/);
  }).pipe(Effect.provide(auditLayer));

  await Effect.runPromise(effect);
});
