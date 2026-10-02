/**
 * PassiveSentinel - Python Engine Subprocess Client
 * Spawns and manages the underlying Python detection engine over stdio JSON-lines.
 */

import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as readline from "readline";
import { AlertRecord, EngineSummary, BenchmarkMetrics, BundleInfo } from "./protocol";

export class EngineClient {
  private process: ChildProcess | null = null;
  private rl: readline.Interface | null = null;
  private pendingRequests: Map<string, { resolve: (val: any) => void; reject: (err: any) => void }> = new Map();
  private onAlertCallback?: (alert: AlertRecord) => void;
  private onProgressCallback?: (progress: any) => void;
  private bundlePath: string;

  constructor(bundlePath?: string) {
    this.bundlePath = bundlePath || path.resolve(__dirname, "../../models/v0.1");
  }

  private resolvePythonExecutable(): string {
    if (process.env.PASSIVESENTINEL_PYTHON && fs.existsSync(process.env.PASSIVESENTINEL_PYTHON)) {
      return process.env.PASSIVESENTINEL_PYTHON;
    }
    // Check known Windows system Python 3.12 location with PyTorch + CUDA
    const winPy = "C:\\Users\\arpan goyal\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
    if (fs.existsSync(winPy)) {
      return winPy;
    }
    return process.platform === "win32" ? "python" : "python3";
  }

  public async start(): Promise<void> {
    if (this.process) return;

    const pythonBin = this.resolvePythonExecutable();
    const serverScript = path.resolve(__dirname, "../../engine/server.py");

    if (!fs.existsSync(serverScript)) {
      throw new Error(`Engine server script not found: ${serverScript}`);
    }

    this.process = spawn(pythonBin, [serverScript, "--stdio", "--bundle", this.bundlePath], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PYTHONUNBUFFERED: "1" }
    });

    if (!this.process.stdout || !this.process.stdin) {
      throw new Error("Failed to attach stdio pipes to engine process");
    }

    this.rl = readline.createInterface({
      input: this.process.stdout,
      terminal: false
    });

    this.rl.on("line", (line: string) => {
      this.handleLine(line);
    });

    this.process.stderr?.on("data", (data: Buffer) => {
      // Suppress or forward debug stderr
      const msg = data.toString();
      if (!msg.includes("UserWarning")) {
        // console.error(`[engine stderr] ${msg}`);
      }
    });

    this.process.on("error", (err: Error) => {
      console.error("[Engine Error]", err);
    });

    this.process.on("exit", (code: number | null) => {
      this.process = null;
    });

    // Wait for READY status
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Engine startup timed out")), 15000);
      this.pendingRequests.set("READY", {
        resolve: () => {
          clearTimeout(timer);
          resolve();
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  private handleLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const msg = JSON.parse(trimmed);
      const type = msg.type;

      if (type === "STATUS") {
        if (msg.status === "READY") {
          const req = this.pendingRequests.get("READY");
          if (req) {
            req.resolve(msg);
            this.pendingRequests.delete("READY");
          }
        }
      } else if (type === "ALERT") {
        if (this.onAlertCallback && msg.alert) {
          this.onAlertCallback(msg.alert);
        }
      } else if (type === "PROGRESS") {
        if (this.onProgressCallback) {
          this.onProgressCallback(msg);
        }
      } else if (type === "SUMMARY") {
        const req = this.pendingRequests.get("ANALYZE");
        if (req) {
          req.resolve(msg.summary);
          this.pendingRequests.delete("ANALYZE");
        }
      } else if (type === "INFO") {
        const req = this.pendingRequests.get("INFO");
        if (req) {
          req.resolve(msg.info);
          this.pendingRequests.delete("INFO");
        }
      } else if (type === "VERIFY_RESULT") {
        const req = this.pendingRequests.get("VERIFY");
        if (req) {
          req.resolve(msg);
          this.pendingRequests.delete("VERIFY");
        }
      } else if (type === "BENCHMARK_RESULT") {
        const req = this.pendingRequests.get("BENCHMARK");
        if (req) {
          req.resolve(msg.benchmark);
          this.pendingRequests.delete("BENCHMARK");
        }
      } else if (type === "ERROR") {
        const err = new Error(msg.message || "Engine error");
        (err as any).code = msg.code || 1;
        // Check any pending request
        for (const [key, req] of this.pendingRequests.entries()) {
          req.reject(err);
        }
        this.pendingRequests.clear();
      }
    } catch (e) {
      // Non-JSON stdout message
    }
  }

  private sendCommand(payload: any): void {
    if (!this.process || !this.process.stdin) {
      throw new Error("Engine is not running");
    }
    this.process.stdin.write(JSON.stringify(payload) + "\n");
  }

  public async getInfo(): Promise<BundleInfo> {
    await this.start();
    return new Promise<BundleInfo>((resolve, reject) => {
      this.pendingRequests.set("INFO", { resolve, reject });
      this.sendCommand({ cmd: "GET_INFO" });
    });
  }

  public async verifyBundle(): Promise<{ is_valid: boolean; errors: string[] }> {
    await this.start();
    return new Promise<{ is_valid: boolean; errors: string[] }>((resolve, reject) => {
      this.pendingRequests.set("VERIFY", { resolve, reject });
      this.sendCommand({ cmd: "VERIFY" });
    });
  }

  public async analyzeFlow(
    filePath: string,
    options: any = {},
    onAlert?: (alert: AlertRecord) => void,
    onProgress?: (progress: any) => void
  ): Promise<EngineSummary> {
    await this.start();
    this.onAlertCallback = onAlert;
    this.onProgressCallback = onProgress;

    return new Promise<EngineSummary>((resolve, reject) => {
      this.pendingRequests.set("ANALYZE", { resolve, reject });
      this.sendCommand({
        cmd: "ANALYZE_FLOW",
        path: path.resolve(filePath),
        options
      });
    });
  }

  public async runBenchmark(
    filePath: string,
    labelsPath: string,
    options: any = {}
  ): Promise<BenchmarkMetrics> {
    await this.start();
    return new Promise<BenchmarkMetrics>((resolve, reject) => {
      this.pendingRequests.set("BENCHMARK", { resolve, reject });
      this.sendCommand({
        cmd: "BENCHMARK",
        path: path.resolve(filePath),
        labels_path: labelsPath ? path.resolve(labelsPath) : "",
        options
      });
    });
  }

  public async shutdown(): Promise<void> {
    if (this.process) {
      try {
        this.sendCommand({ cmd: "SHUTDOWN" });
      } catch (e) {}
      this.process.kill();
      this.process = null;
    }
  }
}
