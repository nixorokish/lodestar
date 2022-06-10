import {CachedBeaconStateAllForks, computeEpochAtSlot} from "@chainsafe/lodestar-beacon-state-transition";
import {allForks, bellatrix} from "@chainsafe/lodestar-types";
import {IForkChoice, ExecutionStatus} from "@chainsafe/lodestar-fork-choice";
import {IChainForkConfig} from "@chainsafe/lodestar-config";
import {ILogger, toHexString} from "@chainsafe/lodestar-utils";
import {IMetrics} from "../../metrics/index.js";
import {IExecutionEngine} from "../../executionEngine/index.js";
import {BlockError, BlockErrorCode} from "../errors/index.js";
import {IBeaconClock} from "../clock/index.js";
import {BlockProcessOpts} from "../options.js";
import {IStateRegenerator, RegenCaller} from "../regen/index.js";
import {IBlsVerifier} from "../bls/index.js";
import {IEth1ForBlockProduction} from "../../eth1/index.js";
import {FullyVerifiedBlock, ImportBlockOpts} from "./types.js";
import {verifyBlocksSanityChecks} from "./verifyBlocksSanityChecks.js";
import {verifyBlockStateTransitionOnly} from "./verifyBlockStateTransitionOnly.js";
import {verifyBlocksSignatures} from "./verifyBlocksSignatures.js";
import {verifyBlockExecutionPayloads} from "./verifyBlockExecutionPayloads.js";
import {POS_PANDA_MERGE_TRANSITION_BANNER} from "./utils/pandaMergeTransitionBanner.js";

export type VerifyBlockModules = {
  bls: IBlsVerifier;
  eth1: IEth1ForBlockProduction;
  executionEngine: IExecutionEngine;
  regen: IStateRegenerator;
  clock: IBeaconClock;
  logger: ILogger;
  forkChoice: IForkChoice;
  config: IChainForkConfig;
  metrics: IMetrics | null;
};

/**
 * Fully verify a block to be imported immediately after. Does not produce any side-effects besides adding intermediate
 * states in the state cache through regen.
 */
export async function verifyBlocks(
  chain: VerifyBlockModules,
  blocks: allForks.SignedBeaconBlock[],
  opts: ImportBlockOpts & BlockProcessOpts
): Promise<FullyVerifiedBlock[]> {
  const {relevantBlocks, parentSlots} = verifyBlocksSanityChecks(chain, blocks, opts);

  // No relevant blocks, skip verifyBlocksInEpoch()
  if (relevantBlocks.length === 0) {
    return [];
  }

  const {postStates, executionStatuses} = await verifyBlocksInEpoch(chain, relevantBlocks, opts);

  return blocks.map((block, i) => ({
    block: block,
    postState: postStates[i],
    parentBlockSlot: parentSlots[i],
    executionStatus: executionStatuses[i],
  }));
}

/**
 * Verifies 1 or more blocks are fully valid; from a linear sequence of blocks.
 *
 * To relieve the main thread signatures are verified separately in workers with chain.bls worker pool.
 * In parallel it:
 * - Run full state transition in sequence
 * - Verify all block's signatures in parallel
 * - Submit execution payloads to EL in sequence
 *
 * If there's an error during one of the steps, the rest are aborted with an AbortController.
 */
export async function verifyBlocksInEpoch(
  chain: VerifyBlockModules,
  blocks: allForks.SignedBeaconBlock[],
  opts: BlockProcessOpts & ImportBlockOpts
): Promise<{postStates: CachedBeaconStateAllForks[]; executionStatuses: ExecutionStatus[]}> {
  if (blocks.length === 0) {
    throw Error("Empty partiallyVerifiedBlocks");
  }

  const block0 = blocks[0];
  const epoch = computeEpochAtSlot(block0.message.slot);

  // Ensure all blocks are in the same epoch
  for (let i = 1; i < blocks.length; i++) {
    const blockSlot = blocks[i].message.slot;
    if (epoch !== computeEpochAtSlot(blockSlot)) {
      throw Error(`Block ${i} slot ${blockSlot} not in same epoch ${epoch}`);
    }
  }

  // TODO: Skip in process chain segment
  // Retrieve preState from cache (regen)
  const preState0 = await chain.regen.getPreState(block0.message, RegenCaller.processBlocksInEpoch).catch((e) => {
    throw new BlockError(block0, {code: BlockErrorCode.PRESTATE_MISSING, error: e as Error});
  });

  // Ensure the state is in the same epoch as block0
  if (epoch !== computeEpochAtSlot(preState0.slot)) {
    throw Error(`preState must be dialed to block epoch ${epoch}`);
  }

  const abortController = new AbortController();

  try {
    const [{postStates}, , {executionStatuses, mergeBlockFound}] = await Promise.all([
      // Run state transition only
      // TODO: Ensure it yields to allow flushing to workers and engine API
      verifyBlockStateTransitionOnly(chain, preState0, blocks, abortController.signal, opts),

      // All signatures at once
      verifyBlocksSignatures(chain, preState0, blocks, opts),

      // Execution payloads
      verifyBlockExecutionPayloads(chain, blocks, preState0, abortController.signal, opts),
    ]);

    if (mergeBlockFound !== null) {
      // merge block found and is fully valid = state transition + signatures + execution payload.
      // TODO: Will this banner be logged during syncing?
      logOnPowBlock(chain, mergeBlockFound);
    }

    return {postStates, executionStatuses};
  } finally {
    abortController.abort();
  }
}

function logOnPowBlock(chain: VerifyBlockModules, mergeBlock: bellatrix.BeaconBlock): void {
  const mergeBlockHash = toHexString(chain.config.getForkTypes(mergeBlock.slot).BeaconBlock.hashTreeRoot(mergeBlock));
  const mergeExecutionHash = toHexString(mergeBlock.body.executionPayload.blockHash);
  const mergePowHash = toHexString(mergeBlock.body.executionPayload.parentHash);
  chain.logger.info(POS_PANDA_MERGE_TRANSITION_BANNER);
  chain.logger.info("Execution transitioning from PoW to PoS!!!");
  chain.logger.info("Importing block referencing terminal PoW block", {
    blockHash: mergeBlockHash,
    executionHash: mergeExecutionHash,
    powHash: mergePowHash,
  });
}
