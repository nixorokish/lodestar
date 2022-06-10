/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment */
import {allForks} from "@chainsafe/lodestar-types";
import {ChainEvent} from "../emitter.js";
import {JobItemQueue} from "../../util/queue/index.js";
import {BlockError, BlockErrorCode} from "../errors/index.js";
import {BlockProcessOpts} from "../options.js";
import {verifyBlocks, VerifyBlockModules} from "./verifyBlock.js";
import {importBlock, ImportBlockModules} from "./importBlock.js";
import {assertLinearChainSegment} from "./utils/chainSegment.js";
import {ImportBlockOpts} from "./types.js";
export {ImportBlockOpts};

const QUEUE_MAX_LENGHT = 256;

export type ProcessBlockModules = VerifyBlockModules & ImportBlockModules;

/**
 * BlockProcessor processes block jobs in a queued fashion, one after the other.
 */
export class BlockProcessor {
  readonly jobQueue: JobItemQueue<[allForks.SignedBeaconBlock[], ImportBlockOpts], void>;

  constructor(modules: ProcessBlockModules, opts: BlockProcessOpts, signal: AbortSignal) {
    this.jobQueue = new JobItemQueue<[allForks.SignedBeaconBlock[], ImportBlockOpts], void>(
      (job, importOpts) => {
        return processChainSegment(modules, job, {...opts, ...importOpts});
      },
      {maxLength: QUEUE_MAX_LENGHT, signal},
      modules.metrics ? modules.metrics.blockProcessorQueue : undefined
    );
  }

  async processBlocksJob(job: allForks.SignedBeaconBlock[], opts: ImportBlockOpts = {}): Promise<void> {
    await this.jobQueue.push(job, opts);
  }
}

///////////////////////////
// TODO: Run this functions with spec tests of many blocks
///////////////////////////

/**
 * Validate and process a block
 *
 * The only effects of running this are:
 * - forkChoice update, in the case of a valid block
 * - various events emitted: checkpoint, forkChoice:*, head, block, error:block
 * - (state cache update, from state regeneration)
 *
 * All other effects are provided by downstream event handlers
 */
export async function processChainSegment(
  modules: ProcessBlockModules,
  blocks: allForks.SignedBeaconBlock[],
  opts: BlockProcessOpts & ImportBlockOpts
): Promise<void> {
  if (blocks.length === 0) {
    return; // TODO: or throw?
  } else if (blocks.length > 1) {
    assertLinearChainSegment(modules.config, blocks);
  }

  try {
    const fullyVerifiedBlocks = await verifyBlocks(modules, blocks, opts);

    for (const fullyVerifiedBlock of fullyVerifiedBlocks) {
      // No need to sleep(0) here since `importBlock` includes a disk write
      // TODO: Consider batching importBlock too if it takes significant time
      await importBlock(modules, fullyVerifiedBlock, opts);
    }
  } catch (e) {
    // above functions should only throw BlockError
    const err = getBlockError(e, blocks[0]);
    modules.emitter.emit(ChainEvent.errorBlock, err);

    throw e;
  }
}

function getBlockError(e: unknown, block: allForks.SignedBeaconBlock): BlockError {
  if (e instanceof BlockError) {
    return e;
  } else if (e instanceof Error) {
    const blockError = new BlockError(block, {code: BlockErrorCode.BEACON_CHAIN_ERROR, error: e as Error});
    blockError.stack = e.stack;
    return blockError;
  } else {
    return new BlockError(block, {code: BlockErrorCode.BEACON_CHAIN_ERROR, error: e as Error});
  }
}
