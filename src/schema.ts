import { Schema } from "effect";

export const RUN_STATES = [
  "SCOPED",
  "ANALYZING",
  "VALIDATING",
  "CONFIRMED",
  "REPORT_READY",
  "ABORTED",
  "FAILED",
] as const;

export const OPERATIONS = [
  "forge-build",
  "forge-test",
  "slither",
  "aderyn",
  "halmos",
  "echidna",
  "medusa",
  "cast-code",
] as const;

export const GATE_KEYS = [
  "reproduced",
  "impactInScope",
  "rootCauseInScope",
  "realisticAttacker",
  "notKnownOrIntended",
  "impactDemonstrated",
  "pinnedAndRepeatable",
] as const;

export const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const FINDING_STATUSES = ["candidate", "confirmed", "killed"] as const;

export type RunState = (typeof RUN_STATES)[number];
export type Operation = (typeof OPERATIONS)[number];
export type Severity = (typeof SEVERITIES)[number];
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const TRANSITIONS: Record<RunState, ReadonlySet<RunState>> = {
  SCOPED: new Set(["SCOPED", "ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  ANALYZING: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  VALIDATING: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  CONFIRMED: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  REPORT_READY: new Set(["ANALYZING", "VALIDATING", "CONFIRMED", "REPORT_READY", "ABORTED", "FAILED"]),
  ABORTED: new Set(["ANALYZING", "VALIDATING", "REPORT_READY", "ABORTED"]),
  FAILED: new Set(["ANALYZING", "VALIDATING", "REPORT_READY", "ABORTED", "FAILED"]),
};

export const RunId = Schema.String.pipe(
  Schema.pattern(/^run-[0-9]{8}t[0-9]{6}z-[a-f0-9]{8}$/),
  Schema.brand("RunId"),
);
export type RunId = typeof RunId.Type;

export const FindingId = Schema.String.pipe(
  Schema.pattern(/^finding-[a-f0-9]{12}$/),
  Schema.brand("FindingId"),
);
export type FindingId = typeof FindingId.Type;

export const EthAddress = Schema.String.pipe(
  Schema.pattern(/^0x[a-fA-F0-9]{40}$/),
  Schema.brand("EthAddress"),
);
export type EthAddress = typeof EthAddress.Type;

export interface ValidationGates {
  reproduced: boolean;
  impactInScope: boolean;
  rootCauseInScope: boolean;
  realisticAttacker: boolean;
  notKnownOrIntended: boolean;
  impactDemonstrated: boolean;
  pinnedAndRepeatable: boolean;
}

export const ValidationGatesSchema = Schema.Struct({
  reproduced: Schema.Boolean,
  impactInScope: Schema.Boolean,
  rootCauseInScope: Schema.Boolean,
  realisticAttacker: Schema.Boolean,
  notKnownOrIntended: Schema.Boolean,
  impactDemonstrated: Schema.Boolean,
  pinnedAndRepeatable: Schema.Boolean,
});

export interface Artifact {
  path: string;
  sha256: string;
  size: number;
}

export const ArtifactSchema = Schema.Struct({
  path: Schema.String,
  sha256: Schema.String,
  size: Schema.Number,
});

export interface ScopeManifest {
  kind: "repository" | "contract" | "url";
  target: string;
  targetRoot: string;
  program: string;
  authorization: "user-attested";
  chainId?: number | undefined;
  rpcHost?: string | undefined;
  createdAt: string;
}

export const ScopeManifestSchema = Schema.Struct({
  kind: Schema.Literal("repository", "contract", "url"),
  target: Schema.String,
  targetRoot: Schema.String,
  program: Schema.String,
  authorization: Schema.Literal("user-attested"),
  chainId: Schema.optional(Schema.Number),
  rpcHost: Schema.optional(Schema.String),
  createdAt: Schema.String,
});

export interface HuntRun {
  version: 1;
  id: string;
  state: RunState;
  scope: ScopeManifest;
  createdAt: string;
  updatedAt: string;
  eventCount: number;
  lastEventHash: string;
}

export const HuntRunSchema = Schema.Struct({
  version: Schema.Literal(1),
  id: Schema.String,
  state: Schema.Literal(...RUN_STATES),
  scope: ScopeManifestSchema,
  createdAt: Schema.String,
  updatedAt: Schema.String,
  eventCount: Schema.Number,
  lastEventHash: Schema.String,
});

export interface HuntEvent {
  sequence: number;
  timestamp: string;
  type: string;
  state: RunState;
  data: Record<string, unknown>;
  previousHash: string;
  hash: string;
}

export const HuntEventSchema = Schema.Struct({
  sequence: Schema.Number,
  timestamp: Schema.String,
  type: Schema.String,
  state: Schema.Literal(...RUN_STATES),
  data: Schema.Record({ key: Schema.String, value: Schema.Unknown }),
  previousHash: Schema.String,
  hash: Schema.String,
});

export interface FindingInput {
  title: string;
  severity: Severity;
  status: FindingStatus;
  rootCause: string;
  impact: string;
  reproduction: string;
  gates: ValidationGates;
  evidencePaths: string[];
}

export const FindingInputSchema = Schema.Struct({
  title: Schema.String,
  severity: Schema.Literal(...SEVERITIES),
  status: Schema.Literal(...FINDING_STATUSES),
  rootCause: Schema.String,
  impact: Schema.String,
  reproduction: Schema.String,
  gates: ValidationGatesSchema,
  evidencePaths: Schema.Array(Schema.String),
});

export interface FindingRecord extends FindingInput {
  id: string;
  runId: string;
  createdAt: string;
  evidence: Artifact[];
}

export const FindingRecordSchema = Schema.Struct({
  ...FindingInputSchema.fields,
  id: Schema.String,
  runId: Schema.String,
  createdAt: Schema.String,
  evidence: Schema.Array(ArtifactSchema),
});

export interface ToolCapability {
  name: "forge" | "anvil" | "cast" | "slither" | "aderyn" | "halmos" | "echidna" | "medusa" | "docker";
  available: boolean;
  path?: string | undefined;
}

export const ToolCapabilitySchema = Schema.Struct({
  name: Schema.Literal("forge", "anvil", "cast", "slither", "aderyn", "halmos", "echidna", "medusa", "docker"),
  available: Schema.Boolean,
  path: Schema.optional(Schema.String),
});

export interface OperationInput {
  operation: Operation;
  matchPath?: string | undefined;
  matchContract?: string | undefined;
  matchTest?: string | undefined;
  contractPath?: string | undefined;
  contractName?: string | undefined;
  configPath?: string | undefined;
  forkBlockNumber?: number | undefined;
  timeoutMs?: number | undefined;
}

export const OperationInputSchema = Schema.Struct({
  operation: Schema.Literal(...OPERATIONS),
  matchPath: Schema.optional(Schema.String),
  matchContract: Schema.optional(Schema.String),
  matchTest: Schema.optional(Schema.String),
  contractPath: Schema.optional(Schema.String),
  contractName: Schema.optional(Schema.String),
  configPath: Schema.optional(Schema.String),
  forkBlockNumber: Schema.optional(Schema.Number),
  timeoutMs: Schema.optional(Schema.Number),
});

export interface OperationResult {
  operation: Operation;
  command: string[];
  exitCode: number;
  signal: NodeJS.Signals | string | null;
  durationMs: number;
  stdout: string;
  stderr: string;
  artifacts: Artifact[];
}

export const OperationResultSchema = Schema.Struct({
  operation: Schema.Literal(...OPERATIONS),
  command: Schema.Array(Schema.String),
  exitCode: Schema.Number,
  signal: Schema.Union(Schema.String, Schema.Null),
  durationMs: Schema.Number,
  stdout: Schema.String,
  stderr: Schema.String,
  artifacts: Schema.Array(ArtifactSchema),
});

export interface Hypothesis {
  id: string;
  title: string;
  category: string;
  targetContract: string;
  targetFunction?: string | undefined;
  invariantViolated: string;
  attackVector: string;
  status: "untested" | "validating" | "confirmed" | "killed";
  pocFile?: string | undefined;
  notes?: string | undefined;
}

export const HypothesisSchema = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  category: Schema.String,
  targetContract: Schema.String,
  targetFunction: Schema.optional(Schema.String),
  invariantViolated: Schema.String,
  attackVector: Schema.String,
  status: Schema.Literal("untested", "validating", "confirmed", "killed"),
  pocFile: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
});
