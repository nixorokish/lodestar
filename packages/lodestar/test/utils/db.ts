import child_process from "node:child_process";
import {IFilterOptions, LevelDbController} from "@chainsafe/lodestar-db";
import {IChainForkConfig} from "@chainsafe/lodestar-config";
import {ILogger} from "@chainsafe/lodestar-utils";
import {BeaconDb} from "../../src/index.js";

export const TEMP_DB_LOCATION = ".tmpdb";

export async function startTmpBeaconDb(config: IChainForkConfig, logger: ILogger): Promise<BeaconDb> {
  // Clean-up db first
  child_process.execSync(`rm -rf ${TEMP_DB_LOCATION}`);

  const db = new BeaconDb({
    config,
    controller: new LevelDbController({name: TEMP_DB_LOCATION}, {logger}),
  });
  await db.start();

  return db;
}

/**
 * Helper to filter an array with DB IFilterOptions options
 */
export function filterBy<T>(items: T[], options: IFilterOptions<number>, getter: (item: T) => number): T[] {
  return items.filter(
    (item) =>
      (options.gt === undefined || getter(item) > options.gt) &&
      (options.gte === undefined || getter(item) >= options.gte) &&
      (options.lt === undefined || getter(item) < options.lt) &&
      (options.lte === undefined || getter(item) <= options.lte)
  );
}
