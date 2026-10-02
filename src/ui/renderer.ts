/**
 * PassiveSentinel - Terminal UI & Alert Renderer
 * Beautiful ANSI terminal cards, alert banners, and telemetry formatting.
 */

import chalk from "chalk";
import { AlertRecord, EngineSummary, BundleInfo } from "../engine/protocol";

export class TerminalRenderer {
  public static colorSeverity(level: string): string {
    switch (level.toLowerCase()) {
      case "critical":
        return chalk.bold.red("[CRITICAL]");
      case "high":
        return chalk.bold.yellow("[HIGH    ]");
      case "medium":
        return chalk.bold.cyan("[MEDIUM  ]");
      case "low":
        return chalk.gray("[LOW     ]");
      default:
        return chalk.white(`[${level.toUpperCase()}]`);
    }
  }

  public static renderAlertLine(alert: AlertRecord): void {
    const badge = this.colorSeverity(alert.severity.level);
    const cls = chalk.bold(alert.threat_class.padEnd(16));
    const conf = chalk.green(`conf ${alert.confidence.toFixed(2)}`);
    const flow = chalk.gray(alert.flow_id);
    
    // Extract key facts from evidence
    let evidenceFact = "";
    if (alert.evidence.distinct_dst_ports) {
      evidenceFact = `${alert.evidence.distinct_dst_ports.value || alert.evidence.distinct_dst_ports} distinct ports`;
    } else if (alert.evidence.byte_count) {
      evidenceFact = `${Math.round(alert.evidence.byte_count / 1024)} KB egress`;
    } else if (alert.evidence.packet_count) {
      evidenceFact = `${alert.evidence.packet_count} pkts`;
    }

    console.log(`${badge} ${cls} ${conf} ${flow} ${chalk.italic(evidenceFact)}`);
  }

  public static renderSummary(summary: EngineSummary, outputFile?: string): void {
    console.log("\n" + chalk.bold.cyan("=".repeat(72)));
    console.log(chalk.bold.white("  📊 PASSIVESENTINEL RUN SUMMARY (SIH PS-145)"));
    console.log(chalk.bold.cyan("=".repeat(72)));

    console.log(`  ${chalk.gray("Bundle Version:")}    ${chalk.white(summary.bundle_version)} (schema ${chalk.yellow(summary.schema_hash)})`);
    console.log(`  ${chalk.gray("Input Source:")}      ${chalk.white(summary.input_type)} (${summary.workers} worker threads)`);
    console.log(`  ${chalk.gray("Active Detectors:")}  ${chalk.green(summary.active_detectors.join(", "))}`);
    if (summary.disabled_detectors.length > 0) {
      console.log(`  ${chalk.gray("Disabled Detectors:")}${chalk.gray(summary.disabled_detectors.join(", "))} (unsupported by flow input)`);
    }

    console.log("\n" + chalk.bold("  Ingest & Throughput:"));
    const flows = summary.counters.flows_processed.toLocaleString();
    const pps = summary.throughput_flows_sec.toLocaleString();
    const drops = summary.counters.drops_queue_full;
    const rejections = summary.counters.flows_rejected;

    console.log(`  • Flows Processed:  ${chalk.bold.white(flows)} flows in ${chalk.white(summary.counters.elapsed_s)}s (${chalk.bold.green(pps + " flows/s")})`);
    console.log(`  • Drops / Rejects:  ${drops > 0 ? chalk.red(drops) : chalk.green("0 drops")} | ${rejections} invalid/rejected`);

    console.log("\n" + chalk.bold("  Latency Bounds (Constraint C4):"));
    const p50 = summary.latency_percentiles_ms.p50;
    const p95 = summary.latency_percentiles_ms.p95;
    const p99 = summary.latency_percentiles_ms.p99;
    console.log(`  • p50: ${chalk.green(p50 + " ms")}  |  p95: ${chalk.green(p95 + " ms")}  |  p99: ${chalk.yellow(p99 + " ms")}`);

    console.log("\n" + chalk.bold("  Incident Detections (L8 Alerts):"));
    const sc = summary.severity_counts;
    const totalAlerts = summary.counters.alerts_emitted;
    console.log(`  • Total Alerts:     ${chalk.bold.white(totalAlerts)} incidents`);
    console.log(`  • Breakdown:        ${chalk.red(sc.critical + " Critical")} | ${chalk.yellow(sc.high + " High")} | ${chalk.cyan(sc.medium + " Medium")} | ${chalk.gray(sc.low + " Low")}`);

    if (Object.keys(summary.class_counts).length > 0) {
      console.log("  • Threat Classes:   " + Object.entries(summary.class_counts).map(([k, v]) => `${k}: ${chalk.bold(v)}`).join(", "));
    }

    if (outputFile) {
      console.log(`\n  ${chalk.gray("Alert Stream:")}      ${chalk.cyan(outputFile)}`);
    }
    console.log(chalk.bold.cyan("=".repeat(72)) + "\n");
  }

  public static renderBundleInfo(info: BundleInfo): void {
    console.log("\n" + chalk.bold.cyan("┌" + "─".repeat(60) + "┐"));
    console.log(chalk.bold.cyan("│") + chalk.bold.white("  PASSIVESENTINEL MODEL BUNDLE SPECIFICATION".padEnd(60)) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("├" + "─".repeat(60) + "┤"));
    console.log(chalk.bold.cyan("│") + ` Bundle Version:        ${chalk.yellow(info.bundle_version)}`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("│") + ` Created UTC:           ${chalk.white(info.created_utc)}`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("│") + ` Alert Contract:        ${chalk.white("v" + info.alert_schema_version)}`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("│") + ` Min CLI Version:       ${chalk.white("v" + info.min_cli_version)}`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("│") + ` Feature Schema SHA:    ${chalk.gray(info.feature_schema_sha256.slice(0, 16))}...`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("│") + ` Calibrated Temp (T):   ${chalk.green(info.calibrated_temperature || 1.06)}`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("│") + ` Cryptographic Integrity:${info.artifacts_verified ? chalk.bold.green(" VERIFIED (Valid)") : chalk.red(" UNVERIFIED")}`.padEnd(69) + chalk.bold.cyan("│"));
    console.log(chalk.bold.cyan("├" + "─".repeat(60) + "┤"));
    console.log(chalk.bold.cyan("│") + chalk.bold(" Threat Classes (Canonical 7):".padEnd(60)) + chalk.bold.cyan("│"));
    for (const c of info.classes) {
      console.log(chalk.bold.cyan("│") + `   • ${chalk.white(c)}`.padEnd(69) + chalk.bold.cyan("│"));
    }
    console.log(chalk.bold.cyan("└" + "─".repeat(60) + "┘\n"));
  }
}
