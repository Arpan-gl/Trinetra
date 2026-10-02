/**
 * PassiveSentinel - `model` command handler
 * Inspects and verifies model bundles (Section 6.1 & 9).
 */

import chalk from "chalk";
import { EngineClient } from "../engine/client";
import { TerminalRenderer } from "../ui/renderer";

export async function handleModelInfo(options: { model?: string; json?: boolean }): Promise<void> {
  const client = new EngineClient(options.model);
  try {
    const info = await client.getInfo();
    if (options.json) {
      console.log(JSON.stringify(info, null, 2));
    } else {
      TerminalRenderer.renderBundleInfo(info);
    }
  } catch (err: any) {
    console.error(chalk.red(`[Error] Failed to read model bundle: ${err.message}`));
    process.exit(err.code || 3);
  } finally {
    await client.shutdown();
  }
}

export async function handleModelVerify(options: { model?: string }): Promise<void> {
  const client = new EngineClient(options.model);
  try {
    const res = await client.verifyBundle();
    if (res.is_valid) {
      console.log(chalk.bold.green("✔ [SUCCESS] Model bundle SHA-256 integrity verified. All artifacts match manifest."));
      process.exit(0);
    } else {
      console.error(chalk.bold.red("✖ [FAIL] Model bundle verification failed:"));
      for (const err of res.errors) {
        console.error(chalk.red(`  • ${err}`));
      }
      process.exit(3);
    }
  } catch (err: any) {
    console.error(chalk.red(`[Error] Verification failure: ${err.message}`));
    process.exit(err.code || 3);
  } finally {
    await client.shutdown();
  }
}
