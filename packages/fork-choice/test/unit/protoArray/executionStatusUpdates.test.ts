import {expect} from "chai";
import {ProtoArray, ExecutionStatus, MaybeValidExecutionStatus, BlockExecution} from "../../../src/index.js";

type ValidationTestCase = {
  root: string;
  bestChild?: string;
  bestDescendant?: string;
  executionStatus: ExecutionStatus | undefined;
};

describe("executionStatus updates", () => {
  const blocks: {slot: number; root: string; parent: string; executionStatus: MaybeValidExecutionStatus}[] = [
    {slot: 1, root: "1A", parent: "0", executionStatus: ExecutionStatus.Syncing},
    {slot: 2, root: "2A", parent: "1A", executionStatus: ExecutionStatus.Syncing},
    {slot: 3, root: "3A", parent: "2A", executionStatus: ExecutionStatus.Syncing},
    {slot: 2, root: "2B", parent: "1A", executionStatus: ExecutionStatus.Syncing},
    {slot: 2, root: "3B", parent: "2B", executionStatus: ExecutionStatus.Syncing},
    {slot: 2, root: "2C", parent: "none", executionStatus: ExecutionStatus.Syncing},
    {slot: 3, root: "3C", parent: "2C", executionStatus: ExecutionStatus.Syncing},
  ];

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

  function collectProtoarrayValidationStatus(): ValidationTestCase[] {
    const expectedForkChoice: ValidationTestCase[] = [];

    for (const block of blocks) {
      const blockNode = fc.getNode(block.root);
      const bestChild =
        blockNode?.bestChild !== undefined ? fc.getNodeFromIndex(blockNode.bestChild).blockRoot : undefined;
      const bestDescendant =
        blockNode?.bestDescendant !== undefined ? fc.getNodeFromIndex(blockNode.bestDescendant).blockRoot : undefined;
      expectedForkChoice.push({
        root: block.root,
        bestChild,
        bestDescendant,
        executionStatus: blockNode?.executionStatus,
      });
    }
    return expectedForkChoice;
  }

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

  const preValidationForkChoice = collectProtoarrayValidationStatus();

  it("preValidation forkchoice setup should be correct", () => {
    expect(preValidationForkChoice).to.be.deep.equal([
      {root: "1A", bestChild: "2B", bestDescendant: "3B", executionStatus: ExecutionStatus.Syncing},
      {root: "2A", bestChild: "3A", bestDescendant: "3A", executionStatus: ExecutionStatus.Syncing},
      {root: "3A", bestChild: undefined, bestDescendant: undefined, executionStatus: ExecutionStatus.Syncing},
      {root: "2B", bestChild: "3B", bestDescendant: "3B", executionStatus: ExecutionStatus.Syncing},
      {root: "3B", bestChild: undefined, bestDescendant: undefined, executionStatus: ExecutionStatus.Syncing},
      {root: "2C", bestChild: "3C", bestDescendant: "3C", executionStatus: ExecutionStatus.Syncing},
      {root: "3C", bestChild: undefined, bestDescendant: undefined, executionStatus: ExecutionStatus.Syncing},
    ]);
  });

  // Invalidate 3C but validate 2C with parent none which is not present in forkchoice
  fc.validateLatestHash("2C", "3C");

  const invalidate3CValidate2CForkChoice = collectProtoarrayValidationStatus();
  it("correcly invalidate 3C and validate 2C only", () => {
    expect(invalidate3CValidate2CForkChoice).to.be.deep.equal([
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
        executionStatus: "Valid",
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
  fc.validateLatestHash("3B", null);
  const validate3B2B1A = collectProtoarrayValidationStatus();
  it("Validate 3B, 2B, 1A", () => {
    expect(validate3B2B1A).to.be.deep.equal([
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
        executionStatus: "Valid",
      },
      {
        root: "3C",
        bestChild: undefined,
        bestDescendant: undefined,
        executionStatus: "Invalid",
      },
    ]);
  });

  fc.validateLatestHash("1A", "3A");
  const invalidate3A2A = collectProtoarrayValidationStatus();
  it("Invalidate 3A, 2A with 2A loosing its bestChild, bestDescendant", () => {
    expect(invalidate3A2A).to.be.deep.equal([
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
        executionStatus: "Valid",
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
