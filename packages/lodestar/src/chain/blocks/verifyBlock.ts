import {
  CachedBeaconStateAllForks,
  computeStartSlotAtEpoch,
  isBellatrixStateType,
  isBellatrixBlockBodyType,
  isMergeTransitionBlock as isMergeTransitionBlockFn,
  isExecutionEnabled,
  getBlockSignatureSets,
  stateTransition,
  computeEpochAtSlot,
} from "@chainsafe/lodestar-beacon-state-transition";
import {bellatrix, allForks} from "@chainsafe/lodestar-types";
import {toHexString} from "@chainsafe/ssz";
import {IForkChoice, IProtoBlock, ExecutionStatus, assertValidTerminalPowBlock} from "@chainsafe/lodestar-fork-choice";
import {IChainForkConfig} from "@chainsafe/lodestar-config";
import {ErrorAborted, ILogger, sleep} from "@chainsafe/lodestar-utils";
import {IMetrics} from "../../metrics/index.js";
import {IExecutionEngine} from "../../executionEngine/index.js";
import {BlockError, BlockErrorCode} from "../errors/index.js";
import {IBeaconClock} from "../clock/index.js";
import {BlockProcessOpts} from "../options.js";
import {IStateRegenerator, RegenCaller} from "../regen/index.js";
import {IBlsVerifier} from "../bls/index.js";
import {ExecutePayloadStatus} from "../../executionEngine/interface.js";
import {byteArrayEquals} from "../../util/bytes.js";
import {IEth1ForBlockProduction} from "../../eth1/index.js";
import {FullyVerifiedBlock, ImportBlockOpts} from "./types.js";
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
  const {parentBlock, relevantBlocks} = verifyBlocksSanityChecks(chain, blocks, opts);

  // No relevant blocks, skip verifyBlocksInEpoch()
  if (relevantBlocks.length === 0) {
    return [];
  }

  const {postStates, executionStatuses} = await verifyBlocksInEpoch(chain, relevantBlocks, opts);

  return blocks.map((block, i) => ({
    block: block,
    postState: postStates[i],
    parentBlockSlot: i === 0 ? parentBlock.slot : blocks[i - 1].message.slot,
    executionStatus: executionStatuses[i],
  }));
}

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
  chain: VerifyBlockModules,
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
    const [{postStates}, , {executionStatuses}] = await Promise.all([
      // Run state transition only
      // TODO: Ensure it yields to allow flushing to workers and engine API
      verifyBlockStateTransitionOnly(chain, preState0, blocks, abortController.signal, opts),

      // All signatures at once
      verifyBlocksSignatures(chain, preState0, blocks, opts),

      // Execution payloads
      verifyBlockExecutionPayloads(chain, blocks, preState0, abortController.signal, opts),
    ]);

    return {postStates, executionStatuses};
  } finally {
    abortController.abort();
  }
}

/**
 * Verifies 1 or more blocks are fully valid running the full state transition; from a linear sequence of blocks.
 *
 * - Advance state to block's slot - per_slot_processing()
 * - For each block:
 *   - STFN - per_block_processing()
 *   - Check state root matches
 */
export async function verifyBlockStateTransitionOnly(
  chain: VerifyBlockModules,
  preState0: CachedBeaconStateAllForks,
  blocks: allForks.SignedBeaconBlock[],
  signal: AbortSignal,
  opts: BlockProcessOpts & ImportBlockOpts
): Promise<{postStates: CachedBeaconStateAllForks[]}> {
  const postStates = new Array<CachedBeaconStateAllForks>(blocks.length);

  for (let i = 0; i < blocks.length; i++) {
    const {validProposerSignature, validSignatures} = opts;
    const block = blocks[i];
    const preState = i === 0 ? preState0 : postStates[i - 1];

    // STFN - per_slot_processing() + per_block_processing()
    // NOTE: `regen.getPreState()` should have dialed forward the state already caching checkpoint states
    const useBlsBatchVerify = !opts?.disableBlsBatchVerify;
    const postState = stateTransition(
      preState,
      block,
      {
        // false because it's verified below with better error typing
        verifyStateRoot: false,
        // if block is trusted don't verify proposer or op signature
        verifyProposer: !useBlsBatchVerify && !validSignatures && !validProposerSignature,
        verifySignatures: !useBlsBatchVerify && !validSignatures,
      },
      chain.metrics
    );

    // Check state root matches
    if (!byteArrayEquals(block.message.stateRoot, postState.hashTreeRoot())) {
      throw new BlockError(block, {
        code: BlockErrorCode.INVALID_STATE_ROOT,
        root: postState.hashTreeRoot(),
        expectedRoot: block.message.stateRoot,
        preState,
        postState,
      });
    }

    postStates[i] = postState;

    // If blocks are invalid in execution the main promise could resolve before this loop ends.
    // In that case stop processing blocks and return early.
    if (signal.aborted) {
      throw new ErrorAborted("verifyBlockStateTransitionOnly");
    }

    // this avoids keeping our node busy processing blocks
    if (i < blocks.length - 1) {
      await sleep(0);
    }
  }

  return {postStates};
}

/**
 * Verifies 1 or more block's signatures from a group of blocks in the same epoch.
 * getBlockSignatureSets() guarantees to return the correct signingRoots as long as all blocks belong in the same
 * epoch as `preState0`. Otherwise the shufflings won't be correct.
 *
 * Since all data is known in advance all signatures are verified at once in parallel.
 */
export async function verifyBlocksSignatures(
  chain: VerifyBlockModules,
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

/**
 * Verifies 1 or more execution payloads from a linear sequence of blocks.
 *
 * Since the EL client must be aware of each parent, all payloads must be submited in sequence.
 */
export async function verifyBlockExecutionPayloads(
  chain: VerifyBlockModules,
  blocks: allForks.SignedBeaconBlock[],
  preState0: CachedBeaconStateAllForks,
  signal: AbortSignal,
  opts: BlockProcessOpts
): Promise<{executionStatuses: ExecutionStatus[]}> {
  const executionStatuses = new Array<ExecutionStatus>(blocks.length);

  for (const block of blocks) {
    // If blocks are invalid in consensus the main promise could resolve before this loop ends.
    // In that case stop sending blocks to execution engine
    if (signal.aborted) {
      throw new ErrorAborted("verifyBlockExecutionPayloads");
    }

    const {executionStatus} = await verifyBlockExecutionPayload(chain, block, preState0, opts);
    executionStatuses.push(executionStatus);

    const isMergeTransitionBlock =
      isBellatrixStateType(preState0) &&
      isBellatrixBlockBodyType(block.message.body) &&
      isMergeTransitionBlockFn(preState0, block.message.body);

    // If this is a merge transition block, check to ensure if it references
    // a valid terminal PoW block.
    //
    // However specs define this check to be run inside forkChoice's onBlock
    // (https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/fork-choice.md#on_block)
    // but we perform the check here (as inspired from the lighthouse impl)
    //
    // Reasons:
    //  1. If the block is not valid, we should fail early and not wait till
    //     forkChoice import.
    //  2. It makes logical sense to pair it with the block validations and
    //     deal it with the external services like eth1 tracker here than
    //     in import block
    if (isMergeTransitionBlock) {
      const mergeBlock = block.message as bellatrix.BeaconBlock;
      const mergeBlockHash = toHexString(
        chain.config.getForkTypes(mergeBlock.slot).BeaconBlock.hashTreeRoot(mergeBlock)
      );
      const powBlockRootHex = toHexString(mergeBlock.body.executionPayload.parentHash);
      const powBlock = await chain.eth1.getPowBlock(powBlockRootHex).catch((error) => {
        // Lets just warn the user here, errors if any will be reported on
        // `assertValidTerminalPowBlock` checks
        chain.logger.warn(
          "Error fetching terminal PoW block referred in the merge transition block",
          {powBlockHash: powBlockRootHex, mergeBlockHash},
          error
        );
        return null;
      });
      const powBlockParent =
        powBlock &&
        (await chain.eth1.getPowBlock(powBlock.parentHash).catch((error) => {
          // Lets just warn the user here, errors if any will be reported on
          // `assertValidTerminalPowBlock` checks
          chain.logger.warn(
            "Error fetching parent of the terminal PoW block referred in the merge transition block",
            {powBlockParentHash: powBlock.parentHash, powBlock: powBlockRootHex, mergeBlockHash},
            error
          );
          return null;
        }));

      // executionStatus will never == ExecutionStatus.PreMerge if it's the mergeBlock. But gotta make TS happy =D
      if (executionStatus === ExecutionStatus.PreMerge) {
        throw Error("Merge block must not have executionStatus == PreMerge");
      }

      assertValidTerminalPowBlock(chain.config, mergeBlock, {executionStatus, powBlock, powBlockParent});

      // Valid execution payload, but may not be in a valid beacon chain block. However, this log only prints the
      // execution block's data, so even if the wrapping beacon chain block is invalid, this is still the merge block.
      // However, if the wrapping beacon chain block is invalid this log may happen twice. Note that only blocks valid
      // to gossip validation arrive here, so the signature and proposer are validated.
      logOnPowBlock(chain, mergeBlock);
    }
  }

  return {executionStatuses};
}

/**
 * Verifies a single block execution payload by sending it to the EL client (via HTTP).
 */
export async function verifyBlockExecutionPayload(
  chain: VerifyBlockModules,
  block: allForks.SignedBeaconBlock,
  preState0: CachedBeaconStateAllForks,
  opts: BlockProcessOpts
): Promise<{executionStatus: ExecutionStatus}> {
  /** Not null if execution is enabled */
  const executionPayloadEnabled =
    isBellatrixStateType(preState0) &&
    isBellatrixBlockBodyType(block.message.body) &&
    // Safe to use with a state previous to block's preState. isMergeComplete can only transition from false to true.
    // - If preState0 is after merge block: condition is true, and will always be true
    // - If preState0 is before merge block: the block could lie but then state transition function will throw above
    // It is kinda safe to send non-trusted payloads to the execution client because at most it can trigger sync.
    // TODO: If this becomes a problem, do some basic verification beforehand, like checking the proposer signature.
    isExecutionEnabled(preState0, block.message.body)
      ? block.message.body.executionPayload
      : null;

  if (!executionPayloadEnabled) {
    // isExecutionEnabled() -> false
    return {executionStatus: ExecutionStatus.PreMerge};
  }

  // TODO: Handle better notifyNewPayload() returning error is syncing
  const execResult = await chain.executionEngine.notifyNewPayload(executionPayloadEnabled);

  switch (execResult.status) {
    case ExecutePayloadStatus.VALID:
      chain.forkChoice.validateLatestHash(execResult.latestValidHash, null);
      return {executionStatus: ExecutionStatus.Valid};

    case ExecutePayloadStatus.INVALID: {
      // If the parentRoot is not same as latestValidHash, then the branch from latestValidHash
      // to parentRoot needs to be invalidated
      const parentHashHex = toHexString(block.message.parentRoot);
      chain.forkChoice.validateLatestHash(
        execResult.latestValidHash,
        parentHashHex !== execResult.latestValidHash ? parentHashHex : null
      );
      throw new BlockError(block, {
        code: BlockErrorCode.EXECUTION_ENGINE_ERROR,
        execStatus: execResult.status,
        errorMessage: execResult.validationError ?? "",
      });
    }

    // Accepted and Syncing have the same treatment, as final validation of block is pending
    case ExecutePayloadStatus.ACCEPTED:
    case ExecutePayloadStatus.SYNCING: {
      // It's okay to ignore SYNCING status as EL could switch into syncing
      // 1. On intial startup/restart
      // 2. When some reorg might have occured and EL doesn't has a parent root
      //    (observed on devnets)
      // 3. Because of some unavailable (and potentially invalid) root but there is no way
      //    of knowing if this is invalid/unavailable. For unavailable block, some proposer
      //    will (sooner or later) build on the available parent head which will
      //    eventually win in fork-choice as other validators vote on VALID blocks.
      // Once EL catches up again and respond VALID, the fork choice will be updated which
      // will either validate or prune invalid blocks
      //
      // When to import such blocks:
      // From: https://github.com/ethereum/consensus-specs/pull/2844
      // A block MUST NOT be optimistically imported, unless either of the following
      // conditions are met:
      //
      // 1. Parent of the block has execution
      // 2. The justified checkpoint has execution enabled
      // 3. The current slot (as per the system clock) is at least
      //    SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY ahead of the slot of the block being
      //    imported.

      const parentRoot = toHexString(block.message.parentRoot);
      const parentBlock = chain.forkChoice.getBlockHex(parentRoot);
      const justifiedBlock = chain.forkChoice.getJustifiedBlock();

      if (
        !parentBlock ||
        // Following condition is the !(Not) of the safe import condition
        (parentBlock.executionStatus === ExecutionStatus.PreMerge &&
          justifiedBlock.executionStatus === ExecutionStatus.PreMerge &&
          block.message.slot + opts.safeSlotsToImportOptimistically > chain.clock.currentSlot)
      ) {
        throw new BlockError(block, {
          code: BlockErrorCode.EXECUTION_ENGINE_ERROR,
          execStatus: ExecutePayloadStatus.UNSAFE_OPTIMISTIC_STATUS,
          errorMessage: `not safe to import ${execResult.status} payload within ${opts.safeSlotsToImportOptimistically} of currentSlot, status=${execResult.status}`,
        });
      }

      return {executionStatus: ExecutionStatus.Syncing};
    }

    // If the block has is not valid, or it referenced an invalid terminal block then the
    // block is invalid, however it has no bearing on any forkChoice cleanup
    //
    // There can be other reasons for which EL failed some of the observed ones are
    // 1. Connection refused / can't connect to EL port
    // 2. EL Internal Error
    // 3. Geth sometimes gives invalid merkel root error which means invalid
    //    but expects it to be handled in CL as of now. But we should log as warning
    //    and give it as optimistic treatment and expect any other non-geth CL<>EL
    //    combination to reject the invalid block and propose a block.
    //    On kintsugi devnet, this has been observed to cause contiguous proposal failures
    //    as the network is geth dominated, till a non geth node proposes and moves network
    //    forward
    // For network/unreachable errors, an optimization can be added to replay these blocks
    // back. But for now, lets assume other mechanisms like unknown parent block of a future
    // child block will cause it to replay

    case ExecutePayloadStatus.INVALID_BLOCK_HASH:
    case ExecutePayloadStatus.ELERROR:
    case ExecutePayloadStatus.UNAVAILABLE:
      throw new BlockError(block, {
        code: BlockErrorCode.EXECUTION_ENGINE_ERROR,
        execStatus: execResult.status,
        errorMessage: execResult.validationError,
      });
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
