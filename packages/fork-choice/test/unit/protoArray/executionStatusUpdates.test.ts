import {expect} from "chai";
import {ProtoArray, ExecutionStatus, MaybeValidExecutionStatus, BlockExecution} from "../../../src/index.js";

type ValidationTestCase = {
  root: string;
  bestChild?: string;
  bestDescendant?: string;
  executionStatus: ExecutionStatus | undefined;
};

type TestBlock = {slot: number; root: string; parent: string; executionStatus: MaybeValidExecutionStatus};
const blocks: TestBlock[] = [
  {slot: 1, root: "1A", parent: "0", executionStatus: ExecutionStatus.Syncing},
  {slot: 2, root: "2A", parent: "1A", executionStatus: ExecutionStatus.Syncing},
  {slot: 3, root: "3A", parent: "2A", executionStatus: ExecutionStatus.Syncing},
  {slot: 2, root: "2B", parent: "1A", executionStatus: ExecutionStatus.Syncing},
  {slot: 2, root: "3B", parent: "2B", executionStatus: ExecutionStatus.Syncing},
  {slot: 2, root: "2C", parent: "none", executionStatus: ExecutionStatus.Syncing},
  {slot: 3, root: "3C", parent: "2C", executionStatus: ExecutionStatus.Syncing},
];
const fcRoots: string[] = ["0"];
for (const block of blocks) {
  fcRoots.push(block.root);
}

const expectedPreValidationFC: ValidationTestCase[] = [
  {
    root: "0",
    bestChild: "1A",
    bestDescendant: "3B",
    executionStatus: ExecutionStatus.PreMerge,
  },
  {root: "1A", bestChild: "2B", bestDescendant: "3B", executionStatus: ExecutionStatus.Syncing},
  {root: "2A", bestChild: "3A", bestDescendant: "3A", executionStatus: ExecutionStatus.Syncing},
  {root: "3A", bestChild: undefined, bestDescendant: undefined, executionStatus: ExecutionStatus.Syncing},
  {root: "2B", bestChild: "3B", bestDescendant: "3B", executionStatus: ExecutionStatus.Syncing},
  {root: "3B", bestChild: undefined, bestDescendant: undefined, executionStatus: ExecutionStatus.Syncing},
  {root: "2C", bestChild: "3C", bestDescendant: "3C", executionStatus: ExecutionStatus.Syncing},
  {root: "3C", bestChild: undefined, bestDescendant: undefined, executionStatus: ExecutionStatus.Syncing},
];

function setupForkChoice(): ProtoArray {
  const fc = ProtoArray.initialize({
    slot: 0,
    stateRoot: "-",
    parentRoot: "-",
    blockRoot: "0",

    justifiedEpoch: 0,
    justifiedRoot: "-",
    finalizedEpoch: 0,
    finalizedRoot: "-",

    ...{executionPayloadBlockHash: null, executionStatus: ExecutionStatus.PreMerge},
  });

  for (const block of blocks) {
    const executionData = (block.executionStatus === ExecutionStatus.PreMerge
      ? {executionPayloadBlockHash: null, executionStatus: ExecutionStatus.PreMerge}
      : {executionPayloadBlockHash: block.root, executionStatus: block.executionStatus}) as BlockExecution;
    fc.onBlock({
      slot: block.slot,
      blockRoot: block.root,
      parentRoot: block.parent,
      stateRoot: "-",
      targetRoot: "-",

      justifiedEpoch: 0,
      justifiedRoot: "-",
      finalizedEpoch: 0,
      finalizedRoot: "-",

      ...executionData,
    });
  }

  const deltas = Array.from({length: fc.nodes.length}, () => 0);
  fc.applyScoreChanges({
    deltas,
    proposerBoost: null,
    justifiedEpoch: 0,
    justifiedRoot: "-",
    finalizedEpoch: 0,
    finalizedRoot: "-",
  });
  return fc;
}

describe("executionStatus / normal updates", () => {
  const fc = setupForkChoice();

  const preValidation = collectProtoarrayValidationStatus(fc);
  it("preValidation forkchoice setup should be correct", () => {
    expect(preValidation).to.be.deep.equal(expectedPreValidationFC);
  });

  // Invalidate 3C with LVH on 2C which stays in Syncing
  fc.validateLatestHash({
    executionStatus: ExecutionStatus.Invalid,
    latestValidExecHash: "2C",
    invalidateTillBlockHash: "3C",
  });

  const invalidate3CValidate2CForkChoice = collectProtoarrayValidationStatus(fc);
  it("correcly invalidate 3C and validate 2C only", () => {
    expect(invalidate3CValidate2CForkChoice).to.be.deep.equal([
      {
        root: "0",
        bestChild: "1A",
        bestDescendant: "3B",
        executionStatus: ExecutionStatus.PreMerge,
      },
      {
        root: "1A",
        bestChild: "2B",
        bestDescendant: "3B",
        executionStatus: "Syncing",
      },
      {
        root: "2A",
        bestChild: "3A",
        bestDescendant: "3A",
        executionStatus: "Syncing",
      },
      {
        root: "3A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Syncing",
      },
      {
        root: "2B",
        bestChild: "3B",
        bestDescendant: "3B",
        executionStatus: "Syncing",
      },
      {
        root: "3B",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Syncing",
      },
      {
        root: "2C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Syncing",
      },
      {
        root: "3C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
    ]);
  });

  // Validate 3B, 2B, 1A (premerge)
  fc.validateLatestHash({
    executionStatus: ExecutionStatus.Valid,
    latestValidExecHash: "3B",
    invalidateTillBlockHash: null,
  });
  const validate3B2B1A = collectProtoarrayValidationStatus(fc);
  it("Validate 3B, 2B, 1A", () => {
    expect(validate3B2B1A).to.be.deep.equal([
      {
        root: "0",
        bestChild: "1A",
        bestDescendant: "3B",
        executionStatus: ExecutionStatus.PreMerge,
      },
      {
        root: "1A",
        bestChild: "2B",
        bestDescendant: "3B",
        executionStatus: "Valid",
      },
      {
        root: "2A",
        bestChild: "3A",
        bestDescendant: "3A",
        executionStatus: "Syncing",
      },
      {
        root: "3A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Syncing",
      },
      {
        root: "2B",
        bestChild: "3B",
        bestDescendant: "3B",
        executionStatus: "Valid",
      },
      {
        root: "3B",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Valid",
      },
      {
        root: "2C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Syncing",
      },
      {
        root: "3C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
    ]);
  });

  fc.validateLatestHash({
    executionStatus: ExecutionStatus.Invalid,
    latestValidExecHash: "1A",
    invalidateTillBlockHash: "3A",
  });
  const invalidate3A2A = collectProtoarrayValidationStatus(fc);
  it("Invalidate 3A, 2A with 2A loosing its bestChild, bestDescendant", () => {
    expect(invalidate3A2A).to.be.deep.equal([
      {
        root: "0",
        bestChild: "1A",
        bestDescendant: "3B",
        executionStatus: ExecutionStatus.PreMerge,
      },
      {
        root: "1A",
        bestChild: "2B",
        bestDescendant: "3B",
        executionStatus: "Valid",
      },
      {
        root: "2A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "3A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "2B",
        bestChild: "3B",
        bestDescendant: "3B",
        executionStatus: "Valid",
      },
      {
        root: "3B",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Valid",
      },
      {
        root: "2C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Syncing",
      },
      {
        root: "3C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
    ]);
  });
});

describe("executionStatus / invalidate all postmerge blocks", () => {
  const fc = setupForkChoice();

  const preValidation = collectProtoarrayValidationStatus(fc);
  it("preValidation forkchoice setup should be correct", () => {
    expect(preValidation).to.be.deep.equal(expectedPreValidationFC);
  });

  fc.validateLatestHash({
    executionStatus: ExecutionStatus.Invalid,
    latestValidExecHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    invalidateTillBlockHash: "3B",
  });
  const postMergeInvalidated = collectProtoarrayValidationStatus(fc);
  it("all post merge blocks should be invalidated", () => {
    expect(postMergeInvalidated).to.be.deep.equal([
      {
        root: "0",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: ExecutionStatus.PreMerge,
      },
      {
        root: "1A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "2A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "3A",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "2B",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "3B",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "2C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
      {
        root: "3C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
    ]);
  });

  const fcHead = fc.findHead("0");
  it("pre merge block should be the FC head", () => {
    expect(fcHead).to.be.equal("0");
  });
});

function collectProtoarrayValidationStatus(fcArray: ProtoArray): ValidationTestCase[] {
  const expectedForkChoice: ValidationTestCase[] = [];

  for (const fcRoot of fcRoots) {
    const fcNode = fcArray.getNode(fcRoot);
    const bestChild =
      fcNode?.bestChild !== undefined ? fcArray.getNodeFromIndex(fcNode.bestChild).blockRoot : undefined;
    const bestDescendant =
      fcNode?.bestDescendant !== undefined ? fcArray.getNodeFromIndex(fcNode.bestDescendant).blockRoot : undefined;
    expectedForkChoice.push({
      root: fcRoot,
      bestChild,
      bestDescendant,
      executionStatus: fcNode?.executionStatus,
    });
  }
  return expectedForkChoice;
}
