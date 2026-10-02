/**
 * PassiveSentinel - `analyze-flow` command handler
 * Runs offline L1-L8 threat detection on NetFlow/IPFIX/CSV flows.
 */

import chalk from "chalk";
import * as fs from "fs";
import { EngineClient } from "../engine/client";
import { AlertSink } from "../alerts/sink";
import { validateAlert } from "../alerts/schema";
import { TerminalRenderer } from "../ui/renderer";
import { AlertRecord } from "../engine/protocol";

export async function handleAnalyzeFlow(filePath: string, options: {
  model?: string;
  output?: string;
  format?: string;
  minSeverity?: string;
  minConfidence?: number;
  workers?: number;
  anonymize?: boolean;
  quiet?: boolean;
}): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`[Error] Input flow file not found: ${filePath}`));
    process.exit(4);
  }

  const client = new EngineClient(options.model);
  const sink = new AlertSink(options.output);

  try {
    const isPretty = options.format !== "jsonl" && !options.quiet;

    if (isPretty) {
      console.log(chalk.bold.cyan("\n[PassiveSentinel] Starting Flow Threat Ingestion & Analysis..."));
      console.log(chalk.gray(`Input: ${filePath}`));
    }

    const summary = await client.analyzeFlow(
      filePath,
      {
        min_severity: options.minSeverity || "low",
        min_confidence: options.minConfidence || 0.0,
        anonymize: options.anonymize || false,
        workers: options.workers || 1
      },
      (alert: AlertRecord) => {
        // Validate schema
        const val = validateAlert(alert);
        if (!val.valid) {
          console.error(chalk.yellow(`[Schema Warning] Alert validation warning: ${val.errors.join(", ")}`));
        }

        // Write to sink
        sink.write(alert);

        // Terminal render
        if (options.format === "jsonl") {
          console.log(JSON.stringify(alert));
        } else if (isPretty) {
          TerminalRenderer.renderAlertLine(alert);
        }
      }
    );

    await sink.close();

    if (isPretty) {
      TerminalRenderer.renderSummary(summary, options.output);
    }

    process.exit(0);

  } catch (err: any) {
    console.error(chalk.red(`[Pipeline Error] ${err.message}`));
    process.exit(err.code || 1);
  } finally {
    await client.shutdown();
  }
}
