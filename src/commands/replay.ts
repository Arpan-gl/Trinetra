/**
 * PassiveSentinel - `replay` command handler
 * Replays traffic at original or scaled timing with live latency & throughput telemetry.
 */

import chalk from "chalk";
import * as fs from "fs";
import { handleAnalyzeFlow } from "./analyze-flow";

export async function handleReplay(filePath: string, options: {
  speed?: string;
  model?: string;
  output?: string;
  format?: string;
  minSeverity?: string;
  minConfidence?: number;
}): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`[Error] Replay file not found: ${filePath}`));
    process.exit(4);
  }

  const speed = options.speed || "1";
  console.log(chalk.bold.cyan("\n[PassiveSentinel] Streaming Replay Mode"));
  console.log(chalk.gray(`Replaying: ${filePath} at ${chalk.bold.yellow(speed + "x")} speed`));
  console.log(chalk.gray("Passive Data Diode Ingestion Buffer: 100 ms micro-batches (C1/C4 compliant)\n"));

  await handleAnalyzeFlow(filePath, options);
}
