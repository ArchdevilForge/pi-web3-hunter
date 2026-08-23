import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  buildReport,
  createRun,
  getRunSummary,
  recordFinding,
  runOperation,
  verifyRun,
  type ValidationGates,
} from "../src/core.js";
import { tokenize } from "../src/extension.js";

const passingGates: ValidationGates = {
  reproduced: true,
  impactInScope: true,
  rootCauseInScope: true,
  realisticAttacker: true,
  notKnownOrIntended: true,
  impactDemonstrated: true,
  pinnedAndRepeatable: true,
};

test("authorized run, validation gates, report, and evidence integrity", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "pi-web3-hunter-"));
  const workspace = join(temporary, "workspace");
  const repository = join(workspace, "protocol");
  await mkdir(repository, { recursive: true });
  await writeFile(join(repository, "foundry.toml"), "[profile.default]\nsrc = 'src'\n");
  const previousState = process.env.WEB3_HUNTER_STATE_DIR;
  process.env.WEB3_HUNTER_STATE_DIR = join(temporary, "state");

  try {
    await assert.rejects(
      createRun({ cwd: workspace, target: "protocol", program: "test-program", authorized: false }),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "AUTHORIZATION_REQUIRED",
    );
    await assert.rejects(
      createRun({ cwd: repository, target: "..", program: "test-program", authorized: true }),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "OUTSIDE_WORKSPACE",
    );

    const run = await createRun({ cwd: workspace, target: "protocol", program: "test-program", authorized: true });
    assert.match(run.id, /^run-/);
    assert.equal((await getRunSummary(run.id)).run.state, "SCOPED");
    assert.deepEqual(await verifyRun(run.id), {
      valid: true,
      eventCount: 1,
      artifactCount: 0,
      lastEventHash: (await getRunSummary(run.id)).run.lastEventHash,
    });

    await assert.rejects(
      runOperation(run.id, { operation: "forge-build" }, { allowHostExec: false }),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "HOST_EXEC_DISABLED",
    );

    const fakeBin = join(repository, "bin");
    const fakeForge = join(fakeBin, "forge");
    await mkdir(fakeBin);
    await writeFile(fakeForge, "#!/bin/sh\necho untrusted\n");
    await chmod(fakeForge, 0o755);
    const previousPath = process.env.PATH;
    process.env.PATH = fakeBin;
    try {
      const executableTestRun = await createRun({ cwd: workspace, target: "protocol", program: "test-program", authorized: true });
      await assert.rejects(
        runOperation(executableTestRun.id, { operation: "forge-build" }, { allowHostExec: true }),
        (error: unknown) => error instanceof Error && "code" in error && error.code === "TOOL_MISSING",
      );
    } finally {
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
    }

    await writeFile(join(repository, "proof.txt"), "reproduced on local fork\n");
    await assert.rejects(
      recordFinding(run.id, {
        title: "Broken accounting invariant",
        severity: "high",
        status: "confirmed",
        rootCause: "A withdrawal path omits the debt update.",
        impact: "An unprivileged account withdraws more assets than deposited.",
        reproduction: "Run forge test --match-test test_Exploit against the pinned block.",
        gates: { ...passingGates, impactDemonstrated: false },
        evidencePaths: ["proof.txt"],
      }),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "VALIDATION_FAILED",
    );

    const finding = await recordFinding(run.id, {
      title: "Broken accounting invariant",
      severity: "high",
      status: "confirmed",
      rootCause: "A withdrawal path omits the debt update.",
      impact: "An unprivileged account withdraws more assets than deposited.",
      reproduction: "Run forge test --match-test test_Exploit against the pinned block.",
      gates: passingGates,
      evidencePaths: ["proof.txt"],
    });
    assert.equal(finding.evidence.length, 1);
    assert.equal((await getRunSummary(run.id)).findings.confirmed, 1);

    const findingPath = join(temporary, "state", "runs", run.id, "findings", `${finding.id}.json`);
    const originalFinding = await readFile(findingPath);
    await writeFile(findingPath, "{}\n");
    await assert.rejects(
      buildReport(run.id),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "CORRUPT_ARTIFACT",
    );
    await writeFile(findingPath, originalFinding);

    const reportPath = await buildReport(run.id);
    assert.match(await readFile(reportPath, "utf8"), /Broken accounting invariant/);
    const verified = await verifyRun(run.id);
    assert.equal(verified.valid, true);
    assert.equal(verified.artifactCount, 3);

    const artifact = finding.evidence[0];
    assert.ok(artifact);
    await writeFile(artifact.path, "tampered\n");
    await assert.rejects(
      verifyRun(run.id),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "CORRUPT_ARTIFACT",
    );
  } finally {
    if (previousState === undefined) delete process.env.WEB3_HUNTER_STATE_DIR;
    else process.env.WEB3_HUNTER_STATE_DIR = previousState;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("slash command tokenizer preserves quoted arguments", () => {
  assert.deepEqual(tokenize(`. --program "Example Bounty" --authorized`), [".", "--program", "Example Bounty", "--authorized"]);
  assert.throws(() => tokenize(`. --program "unterminated`), /Unclosed quote/);
});

test("createRun supports URL targets for DApp and web audits", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "pi-web3-hunter-url-"));
  const previousState = process.env.WEB3_HUNTER_STATE_DIR;
  process.env.WEB3_HUNTER_STATE_DIR = join(temporary, "state");

  try {
    const run = await createRun({
      cwd: temporary,
      target: "https://app.uniswap.org/#/swap",
      program: "Uniswap DApp",
      authorized: true,
    });
    assert.equal(run.scope.kind, "url");
    assert.equal(run.scope.target, "https://app.uniswap.org/#/swap");
    assert.equal(run.scope.program, "Uniswap DApp");

    const runAutoProgram = await createRun({
      cwd: temporary,
      target: "https://docs.aave.com/developers",
      program: "Local Workspace",
      authorized: true,
    });
    assert.equal(runAutoProgram.scope.kind, "url");
    assert.equal(runAutoProgram.scope.program, "docs.aave.com");
  } finally {
    if (previousState === undefined) delete process.env.WEB3_HUNTER_STATE_DIR;
    else process.env.WEB3_HUNTER_STATE_DIR = previousState;
    await rm(temporary, { recursive: true, force: true });
  }
});
