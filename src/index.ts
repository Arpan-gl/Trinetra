/**
 * PassiveSentinel - Main CLI Dispatcher (SIH PS-145)
 * Command-line tool wrapping the trained, verified detection pipeline.
 */

import { Command } from "commander";
import { handleAnalyze } from "./commands/analyze";
import { handleReplay } from "./commands/replay";
import { handleAnalyzeFlow } from "./commands/analyze-flow";
import { handleModelInfo, handleModelVerify } from "./commands/model";
import { handleBenchmark } from "./commands/benchmark";
import { handleReport } from "./commands/report";
import { handleDoctor } from "./commands/doctor";

const program = new Command();

program
  .name("passivesentinel")
  .description("Passive streaming network threat intelligence CLI (SIH PS-145)")
  .version("0.1.0");

// 1. analyze <pcap>
program
  .command("analyze <file>")
  .description("Offline passive threat detection through Layers L0-L8 on PCAP or flow file")
  .option("-m, --model <path>", "Path to model bundle directory")
  .option("-o, --output <file>", "Output file for alert JSON lines")
  .option("-f, --format <format>", "Terminal output format (pretty | jsonl)", "pretty")
  .option("--min-severity <level>", "Filter alerts below severity level (low | medium | high | critical)", "low")
  .option("--min-confidence <float>", "Filter alerts below calibrated confidence threshold", (v) => parseFloat(v), 0.0)
  .option("-w, --workers <N>", "Number of worker processes", (v) => parseInt(v), 1)
  .option("--anonymize", "Hash internal IP entities in output evidence", false)
  .action((file, options) => {
    handleAnalyze(file, options);
  });

// 2. replay <file>
program
  .command("replay <file>")
  .description("Streaming replay at original or scaled timing with live latency & throughput telemetry")
  .option("-s, --speed <speed>", "Timing scale factor (e.g. 1, 5, 10, max)", "1")
  .option("-m, --model <path>", "Path to model bundle directory")
  .option("-o, --output <file>", "Output file for alert JSON lines")
  .option("-f, --format <format>", "Terminal output format (pretty | jsonl)", "pretty")
  .option("--min-severity <level>", "Filter alerts below severity level", "low")
  .option("--min-confidence <float>", "Filter alerts below confidence", (v) => parseFloat(v), 0.0)
  .action((file, options) => {
    handleReplay(file, options);
  });

// 3. analyze-flow <flows.csv>
program
  .command("analyze-flow <file>")
  .description("Enters at L1 and runs threat classification on NetFlow/IPFIX/CSV flows")
  .option("-m, --model <path>", "Path to model bundle directory")
  .option("-o, --output <file>", "Output file for alert JSON lines")
  .option("-f, --format <format>", "Terminal output format (pretty | jsonl)", "pretty")
  .option("--min-severity <level>", "Filter alerts below severity level", "low")
  .option("--min-confidence <float>", "Filter alerts below confidence", (v) => parseFloat(v), 0.0)
  .option("-w, --workers <N>", "Number of worker processes", (v) => parseInt(v), 1)
  .option("--anonymize", "Hash internal IP entities in output evidence", false)
  .action((file, options) => {
    handleAnalyzeFlow(file, options);
  });

// 4. model info & model verify
const modelCmd = program.command("model").description("Inspect and verify versioned model bundles");

modelCmd
  .command("info")
  .description("Print bundle version, schema hash, classes, and thresholds")
  .option("-m, --model <path>", "Path to model bundle directory")
  .option("--json", "Output as raw JSON", false)
  .action((options) => {
    handleModelInfo(options);
  });

modelCmd
  .command("verify")
  .description("Recompute SHA-256 signatures and verify bundle integrity against manifest")
  .option("-m, --model <path>", "Path to model bundle directory")
  .action((options) => {
    handleModelVerify(options);
  });

// 5. benchmark <file> --labels <labels>
program
  .command("benchmark <file>")
  .description("Execute held-out test evaluation reproducing Table 6.6 results without parameter tuning")
  .option("-l, --labels <file>", "Path to ground-truth labels file")
  .option("-m, --model <path>", "Path to model bundle directory")
  .option("-o, --output <file>", "Output benchmark JSON path", "benchmark.json")
  .action((file, options) => {
    handleBenchmark(file, options);
  });

// 6. report <alerts.jsonl>
program
  .command("report <file>")
  .description("Generate human-readable Markdown or HTML incident report from alerts JSONL")
  .option("-o, --output <file>", "Output report path", "passivesentinel_report.md")
  .action((file, options) => {
    handleReport(file, options);
  });

// 7. doctor
program
  .command("doctor")
  .description("Check host enclave environment, interface passivity, and model integrity")
  .option("-i, --interface <name>", "Network interface to check for passive receive-only compliance")
  .option("-m, --model <path>", "Path to model bundle directory")
  .action((options) => {
    handleDoctor(options);
  });

program.parse(process.argv);
