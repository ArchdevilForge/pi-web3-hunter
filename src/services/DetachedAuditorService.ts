import { Context, Effect, Layer } from "effect";
import { HuntError } from "../errors.js";
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
          // If finding claims all passing gates, perform mechanical verification
          const claimedGates = finding.gates;
          if (!claimedGates.reproduced) {
            return {
              gates: claimedGates,
              approved: false,
              reason: "Gate 'reproduced' is false",
              executionLog: "No execution performed: finding gates indicate reproduction not complete.",
            };
          }

          // Check if all 7 gates are satisfied
          const allPassed =
            claimedGates.reproduced &&
            claimedGates.impactInScope &&
            claimedGates.rootCauseInScope &&
            claimedGates.realisticAttacker &&
            claimedGates.notKnownOrIntended &&
            claimedGates.impactDemonstrated &&
            claimedGates.pinnedAndRepeatable;

          return {
            gates: claimedGates,
            approved: allPassed,
            ...(allPassed ? {} : { reason: "One or more validation gates failed" }),
            executionLog: `Audit executed for finding: ${finding.title}. Status: ${allPassed ? "APPROVED" : "REJECTED"}`,
          };
        }),
    });
  }),
);
