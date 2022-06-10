import {CachedBeaconStateAllForks, getBlockSignatureSets} from "@chainsafe/lodestar-beacon-state-transition";
import {allForks} from "@chainsafe/lodestar-types";
import {sleep} from "@chainsafe/lodestar-utils";
import {IBlsVerifier} from "../bls/index.js";
import {BlockError, BlockErrorCode} from "../errors/blockError.js";
import {ImportBlockOpts} from "./types.js";

/**
 * Verifies 1 or more block's signatures from a group of blocks in the same epoch.
 * getBlockSignatureSets() guarantees to return the correct signingRoots as long as all blocks belong in the same
 * epoch as `preState0`. Otherwise the shufflings won't be correct.
 *
 * Since all data is known in advance all signatures are verified at once in parallel.
 */
export async function verifyBlocksSignatures(
  chain: {bls: IBlsVerifier},
  preState0: CachedBeaconStateAllForks,
  blocks: allForks.SignedBeaconBlock[],
  opts: ImportBlockOpts
): Promise<void> {
  const isValidPromises: Promise<boolean>[] = [];

  // Verifies signatures after running state transition, so all SyncCommittee signed roots are known at this point.
  // We must ensure block.slot <= state.slot before running getAllBlockSignatureSets().
  // NOTE: If in the future multiple blocks signatures are verified at once, all blocks must be in the same epoch
  // so the attester and proposer shufflings are correct.
  for (const block of blocks) {
    // Skip all signature verification
    if (opts.validSignatures) {
      continue;
    }

    const signatureSetsBlock = getBlockSignatureSets(preState0, block, {
      skipProposerSignature: opts.validProposerSignature,
    });

    isValidPromises.push(chain.bls.verifySignatureSets(signatureSetsBlock));

    // getBlockSignatureSets() takes 45ms in benchmarks for 2022Q2 mainnet blocks (100 sigs). When syncing a 32 blocks
    // segments it will block the event loop for 1400 ms, which is too much. This sleep will allow the event loop to
    // yield, which will cause one block's state transition to run. However, the tradeoff is okay and doesn't slow sync
    if (isValidPromises.length % 8 === 0) {
      await sleep(0);
    }
  }

  // TODO: Submit each block's signature as a separate job to track which blocks are valid
  if (isValidPromises.length > 0) {
    const isValid = (await Promise.all(isValidPromises)).every((isValid) => isValid === true);
    if (!isValid) {
      throw new BlockError(blocks[0], {code: BlockErrorCode.INVALID_SIGNATURE, state: preState0});
    }
  }
}
