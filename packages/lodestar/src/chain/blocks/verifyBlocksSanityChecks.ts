import {computeStartSlotAtEpoch} from "@chainsafe/lodestar-beacon-state-transition";
import {IChainForkConfig} from "@chainsafe/lodestar-config";
import {IForkChoice, IProtoBlock} from "@chainsafe/lodestar-fork-choice";
import {allForks} from "@chainsafe/lodestar-types";
import {toHexString} from "@chainsafe/lodestar-utils";
import {IBeaconClock} from "../clock/interface.js";
import {BlockError, BlockErrorCode} from "../errors/index.js";
import {ImportBlockOpts} from "./types.js";

/**
 * Verifies some early cheap sanity checks on the block before running the full state transition.
 *
 * - Parent is known to the fork-choice
 * - Check skipped slots limit
 * - check_block_relevancy()
 *   - Block not in the future
 *   - Not genesis block
 *   - Block's slot is < Infinity
 *   - Not finalized slot
 *   - Not already known
 */
export function verifyBlocksSanityChecks(
  chain: {forkChoice: IForkChoice; clock: IBeaconClock; config: IChainForkConfig},
  blocks: allForks.SignedBeaconBlock[],
  opts: ImportBlockOpts
): {parentBlock: IProtoBlock; relevantBlocks: allForks.SignedBeaconBlock[]} {
  if (blocks.length === 0) {
    throw Error("Empty partiallyVerifiedBlocks");
  }

  const block0 = blocks[0];
  const block0Slot = block0.message.slot;

  let ignoreFirstblock = false;
  // Conditions only necessary to check on the first block of the chain, after assertLinearChainSegment()
  // - If first block is > 0, the rest are
  // - If first block is after finalized slot, the rest are
  // - If first block parent is known, the rest are
  // Not genesis block
  // IGNORE if `partiallyVerifiedBlock.ignoreIfKnown`

  if (block0Slot === 0) {
    if (opts.ignoreIfKnown) {
      ignoreFirstblock = true;
    } else {
      throw new BlockError(block0, {code: BlockErrorCode.GENESIS_BLOCK});
    }
  }

  // Not finalized slot
  // IGNORE if `partiallyVerifiedBlock.ignoreIfFinalized`
  const finalizedSlot = computeStartSlotAtEpoch(chain.forkChoice.getFinalizedCheckpoint().epoch);
  if (block0Slot <= finalizedSlot) {
    if (opts.ignoreIfFinalized) {
      ignoreFirstblock = true;
    } else {
      throw new BlockError(block0, {
        code: BlockErrorCode.WOULD_REVERT_FINALIZED_SLOT,
        blockSlot: block0Slot,
        finalizedSlot,
      });
    }
  }

  // Parent is known to the fork-choice
  const parentRoot = toHexString(block0.message.parentRoot);
  const parentBlock = chain.forkChoice.getBlockHex(parentRoot);
  if (!parentBlock) {
    throw new BlockError(block0, {code: BlockErrorCode.PARENT_UNKNOWN, parentRoot});
  }

  const relevantBlocks = blocks.filter((block, i) => {
    const blockSlot = block.message.slot;

    // Conditions only necessary to check on the first block of the chain, after assertLinearChainSegment()
    if (i === 0 && ignoreFirstblock) {
      return false;
    }

    // Block not in the future, also checks for infinity
    const currentSlot = chain.clock.currentSlot;
    if (blockSlot > currentSlot) {
      throw new BlockError(block, {code: BlockErrorCode.FUTURE_SLOT, blockSlot, currentSlot});
    }

    // Not already known
    // IGNORE if `partiallyVerifiedBlock.ignoreIfKnown`
    const blockHash = toHexString(
      chain.config.getForkTypes(block.message.slot).BeaconBlock.hashTreeRoot(block.message)
    );
    if (chain.forkChoice.hasBlockHex(blockHash)) {
      if (opts.ignoreIfKnown) {
        return false;
      } else {
        throw new BlockError(block, {code: BlockErrorCode.ALREADY_KNOWN, root: blockHash});
      }
    }

    return true;
  });

  return {parentBlock, relevantBlocks};
}
