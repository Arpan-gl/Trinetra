/**
 * PassiveSentinel - `benchmark` command handler (Section 12)
 * Evaluates detection quality, calibration, throughput, and latency on locked test split.
 */

import chalk from "chalk";
import * as fs from "fs";
import * as path from "path";
import { EngineClient } from "../engine/client";

export async function handleBenchmark(filePath: string, options: {
  labels?: string;
  model?: string;
  output?: string;
}): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`[Error] Test split file not found: ${filePath}`));
    process.exit(4);
  }

  const client = new EngineClient(options.model);
  const labelsFile = options.labels || "";

  try {
    console.log(chalk.bold.cyan("\n[PassiveSentinel Benchmark Suite]"));
    console.log(chalk.gray(`Evaluating locked test split: ${filePath}`));
    if (labelsFile) {
      console.log(chalk.gray(`Ground-truth labels: ${labelsFile}`));
    }
    console.log(chalk.yellow("Executing zero-tuning evaluation across Layers L0 to L8...\n"));

    const res = await client.runBenchmark(filePath, labelsFile);

    console.log(chalk.bold.cyan("=".repeat(72)));
    console.log(chalk.bold.white("  🎯 HELD-OUT TEST BENCHMARK RESULTS (Section 6.6)"));
    console.log(chalk.bold.cyan("=".repeat(72)));

    console.log(`  • Evaluated Flows:            ${chalk.bold.white(res.flows_evaluated.toLocaleString())}`);
    console.log(`  • Macro-F1 (Entity Disjoint): ${chalk.bold.green(res.macro_f1.toFixed(4))} (Honest zero-leakage score)`);
    console.log(`  • Weighted-F1:                ${chalk.bold.green(res.weighted_f1.toFixed(4))}`);
    console.log(`  • Matthews Correlation (MCC): ${chalk.bold.green(res.matthews_corrcoef.toFixed(4))}`);
    console.log(`  • Expected Calibration Error: ${chalk.cyan(res.expected_calibration_error.toFixed(4))}`);

    console.log("\n" + chalk.bold("  Per-Class Performance:"));
    const classes = Object.keys(res.per_class).filter(k => !["accuracy", "macro avg", "weighted avg"].includes(k));
    for (const c of classes) {
      const row = res.per_class[c];
      const p = (row.precision || 0).toFixed(2);
      const r = (row.recall || 0).toFixed(2);
      const f1 = (row["f1-score"] || 0).toFixed(4);
      const sup = (row.support || 0).toLocaleString();
      console.log(`    - ${chalk.bold(c.padEnd(18))}: F1=${chalk.bold.green(f1)} (Prec: ${p}, Rec: ${r}, Support: ${sup})`);
    }

    const outPath = options.output || path.resolve("benchmark.json");
    fs.writeFileSync(outPath, JSON.stringify(res, null, 2), "utf-8");
    console.log(`\n  ${chalk.gray("Full Benchmark Report:")}     ${chalk.cyan(outPath)}`);
    console.log(chalk.bold.cyan("=".repeat(72)) + "\n");

    process.exit(0);

  } catch (err: any) {
    console.error(chalk.red(`[Benchmark Error] ${err.message}`));
    process.exit(err.code || 1);
  } finally {
    await client.shutdown();
  }
}
