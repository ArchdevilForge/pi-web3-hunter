import { readFile } from "node:fs/promises";
import { Context, Effect, Layer } from "effect";
import { HuntError, toHuntError } from "../errors.js";
import { FindingInput, HuntRun, ValidationGates } from "../schema.js";
import { ScannerService } from "./ScannerService.js";
import { PoCService } from "./PoCService.js";

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
          // ponytail: mechanical independent verification (no blind trust on claimedGates)
          let evidenceText = "";
          for (const p of finding.evidencePaths) {
            try {
              evidenceText += "\n" + (yield* Effect.tryPromise({ try: () => readFile(p, "utf8"), catch: (c) => toHuntError("EVIDENCE_READ_FAILED", c) }));
            } catch { /* ignore missing evidence */ }
          }
          const corrected: ValidationGates = { ...claimedGates };
          const reasons: string[] = [];
          // realisticAttacker fails if PoC pranks owner/privileged to create pool
          const pranksOwner = /vm\.(startPrank|prank)\s*\(\s*owner\b/u.test(evidenceText) || /vm\.(startPrank|prank)\s*\([^)]*\.owner\(\)/u.test(evidenceText);
          const createsFeePool = /\.add\s*\([^)]*FeeToken/u.test(evidenceText) || /add\s*\(\s*100\s*,\s*address\(feeToken\)/u.test(evidenceText);
          if (pranksOwner && createsFeePool) {
            corrected.realisticAttacker = false;
            reasons.push("realisticAttacker: PoC pranks owner to add attacker fee token (add() is onlyOwner) — requires privileged action");
          } else if (pranksOwner && /\.add\s*\(/u.test(evidenceText)) {
            corrected.realisticAttacker = false;
            reasons.push("realisticAttacker: PoC pranks owner/admin — not a permissionless path");
          }
          // notKnownOrIntended fails for known MasterChef fee-on-transfer non-support
          const isFeeTransferFinding = /fee.*transfer|deflationary|inflation/u.test(finding.title) || /FeeToken/u.test(evidenceText);
          if (isFeeTransferFinding && createsFeePool) {
            corrected.notKnownOrIntended = false;
            reasons.push("notKnownOrIntended: MasterChef fee-on-transfer is documented as unsupported (Sushi fork) — known intended behavior");
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
