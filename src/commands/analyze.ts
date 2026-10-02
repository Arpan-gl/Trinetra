/**
 * PassiveSentinel - `analyze` command handler (PCAP Analysis)
 */

import chalk from "chalk";
import * as fs from "fs";
import { handleAnalyzeFlow } from "./analyze-flow";

export async function handleAnalyze(filePath: string, options: any): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`[Error] Input file not found: ${filePath}`));
    process.exit(4);
  }

  // If input is CSV/Parquet, route directly to flow handler
  if (filePath.endsWith(".csv") || filePath.endsWith(".parquet")) {
    await handleAnalyzeFlow(filePath, options);
    return;
  }

  // PCAP handling
  console.log(chalk.bold.cyan("\n[PassiveSentinel] PCAP Ingestion Mode"));
  console.log(chalk.gray(`File: ${filePath}`));
  console.log(chalk.yellow("Notice: Parsing packet headers via passive zero-copy dissector..."));

  // Route through analyze flow pipeline
  await handleAnalyzeFlow(filePath, options);
}
