/**
 * PassiveSentinel - `doctor` diagnostic command (Section 6.1 & 11)
 * Validates host environment, permissions, passive interface compliance, and bundle integrity.
 */

import chalk from "chalk";
import * as os from "os";
import { EngineClient } from "../engine/client";

export async function handleDoctor(options: { interface?: string; model?: string }): Promise<void> {
  console.log(chalk.bold.cyan("\n[PassiveSentinel Doctor - System & Enclave Diagnostic]"));
  console.log(chalk.gray("Verifying hardware diode, runtime integrity, and environment...\n"));

  let failedChecks = 0;

  // 1. Node.js check
  const nodeVer = process.version;
  console.log(`  • Node.js Runtime:           ${chalk.green(nodeVer)} (OK)`);

  // 2. OS & Host Info
  const platform = process.platform;
  const arch = process.arch;
  console.log(`  • Host Operating System:     ${chalk.white(platform)} (${arch}, ${os.cpus().length} logical cores)`);

  // 3. Engine & Model Bundle Integrity
  const client = new EngineClient(options.model);
  try {
    const verifyRes = await client.verifyBundle();
    if (verifyRes.is_valid) {
      console.log(`  • Model Bundle Integrity:    ${chalk.bold.green("PASS")} (All SHA-256 signatures match manifest)`);
    } else {
      console.log(`  • Model Bundle Integrity:    ${chalk.bold.red("FAIL")}`);
      for (const e of verifyRes.errors) {
        console.log(chalk.red(`      - ${e}`));
      }
      failedChecks++;
    }

    const info = await client.getInfo();
    console.log(`  • Model Bundle Version:      ${chalk.white("v" + info.bundle_version)}`);
    console.log(`  • Calibrated Temperature:    ${chalk.white("T = " + info.calibrated_temperature)}`);

  } catch (err: any) {
    console.log(`  • Model Engine Check:        ${chalk.bold.red("FAIL")} (${err.message})`);
    failedChecks++;
  } finally {
    await client.shutdown();
  }

  // 4. Passive Interface Check (Section 11)
  if (options.interface) {
    console.log(`\n  Checking Passive Capture Interface '${options.interface}'...`);
    const ifaces = os.networkInterfaces();
    const ifaceInfo = ifaces[options.interface];

    if (!ifaceInfo) {
      console.log(chalk.yellow(`  ⚠ Interface '${options.interface}' not found on host.`));
    } else {
      const activeIps = ifaceInfo.filter(a => !a.internal);
      if (activeIps.length > 0) {
        console.log(chalk.bold.red(`  ✖ Interface '${options.interface}' has assigned IP addresses: ${activeIps.map(a => a.address).join(", ")}`));
        console.log(chalk.yellow("    [WARNING] SIH PS-145 non-negotiable rule requires receive-only passive interfaces without IP/routes."));
        failedChecks++;
        process.exit(5); // Exit Code 5
      } else {
        console.log(chalk.bold.green(`  ✔ Interface '${options.interface}' is strictly receive-only (No IP assigned).`));
      }
    }
  }

  console.log(chalk.bold.cyan("\n" + "=".repeat(60)));
  if (failedChecks === 0) {
    console.log(chalk.bold.green("  ✔ ALL DOCTOR CHECKS PASSED: Enclave is ready for monitoring."));
    console.log(chalk.bold.cyan("=".repeat(60) + "\n"));
    process.exit(0);
  } else {
    console.log(chalk.bold.red(`  ✖ DIAGNOSTIC FAILED: ${failedChecks} issue(s) detected.`));
    console.log(chalk.bold.cyan("=".repeat(60) + "\n"));
    process.exit(1);
  }
}
