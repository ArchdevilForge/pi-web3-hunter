import { readFile } from "node:fs/promises";
import { Context, Effect, Layer } from "effect";
import { HuntError, toHuntError } from "../errors.js";
import { FindingInput, HuntRun, ValidationGates } from "../schema.js";
import { ScannerService } from "./ScannerService.js";
import { PoCService } from "./PoCService.js";
import { validateFiveAtoms } from "./FirstPrinciplesValidator.js";

export interface DetachedAuditResult {
  readonly gates: ValidationGates;
  readonly approved: boolean;
  readonly reason?: string | undefined;
  readonly executionLog: string;
}

export class DetachedAuditorService extends Context.Tag("DetachedAuditorService")<
  DetachedAuditorService,
  {
    readonly auditFinding: (
      run: HuntRun,
      finding: FindingInput,
      options?: { allowHostExec?: boolean },
    ) => Effect.Effect<DetachedAuditResult, HuntError>;
  }
>() {}

export const DetachedAuditorServiceLive = Layer.effect(
  DetachedAuditorService,
  Effect.gen(function* () {
    const _scanner = yield* ScannerService;
    const _pocService = yield* PoCService;

    return DetachedAuditorService.of({
      auditFinding: (_run, finding, _options) =>
        Effect.gen(function* () {
          const claimedGates = finding.gates;
          if (!claimedGates.reproduced) {
            return {
              gates: claimedGates,
              approved: false,
              reason: "Gate 'reproduced' is false",
              executionLog: "No execution performed: finding gates indicate reproduction not complete.",
            };
          }
          // ponytail: first-principles 5-atom mechanical verification (no blind trust)
          const five = yield* Effect.promise(() => validateFiveAtoms(finding.evidencePaths, finding.title));
          const corrected: ValidationGates = { ...claimedGates };
          const reasons: string[] = [];
          if (!five.permissionless.pass) {
            corrected.realisticAttacker = false;
            reasons.push(five.permissionless.reason!);
          }
          if (!five.novelty.pass) {
            corrected.notKnownOrIntended = false;
            reasons.push(five.novelty.reason!);
          }
          if (!five.scope.pass) {
            corrected.rootCauseInScope = false;
            reasons.push(five.scope.reason!);
          }
          if (!five.state.pass) {
            corrected.pinnedAndRepeatable = false;
            corrected.reproduced = false;
            reasons.push(five.state.reason!);
          }
          if (!five.economic.pass) {
            corrected.impactDemonstrated = false;
            reasons.push(five.economic.reason!);
          }
          // keep legacy explicit checks for fee-token pool (extra safety)
          let evidenceText = "";
          for (const p of finding.evidencePaths) {
            try {
              evidenceText += "\n" + (yield* Effect.tryPromise({ try: () => readFile(p, "utf8"), catch: (c) => toHuntError("EVIDENCE_READ_FAILED", c) }));
            } catch {}
          }
          const pranksOwner = /vm\.(startPrank|prank)\s*\(\s*owner\b/u.test(evidenceText) || /vm\.(startPrank|prank)\s*\([^)]*\.owner\(\)/u.test(evidenceText);
          const createsFeePool = /\.add\s*\([^)]*FeeToken/u.test(evidenceText);
          if (pranksOwner && createsFeePool && corrected.realisticAttacker) {
            corrected.realisticAttacker = false;
            reasons.push("realisticAttacker: pranks owner to add FeeToken");
          }
          const allPassed =
            corrected.reproduced &&
            corrected.impactInScope &&
            corrected.rootCauseInScope &&
            corrected.realisticAttacker &&
            corrected.notKnownOrIntended &&
            corrected.impactDemonstrated &&
            corrected.pinnedAndRepeatable;
          return {
            gates: corrected,
            approved: allPassed,
            ...(allPassed ? {} : { reason: reasons.length ? reasons.join("; ") : "One or more validation gates failed" }),
            executionLog: `Audit executed for finding: ${finding.title}. Status: ${allPassed ? "APPROVED" : "REJECTED"}${reasons.length ? " — " + reasons.join("; ") : ""}`,
          };
        }),
    });
  }),
);
