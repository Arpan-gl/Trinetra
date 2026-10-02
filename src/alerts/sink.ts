/**
 * PassiveSentinel - Alert Stream Writer & File Sink
 * Safely appends validated JSON lines to output sink with file permissions.
 */

import * as fs from "fs";
import * as path from "path";
import { AlertRecord } from "../engine/protocol";

export class AlertSink {
  private filePath?: string;
  private stream?: fs.WriteStream;

  constructor(filePath?: string) {
    if (filePath) {
      this.filePath = path.resolve(filePath);
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      this.stream = fs.createWriteStream(this.filePath, { flags: "a", encoding: "utf-8" });
    }
  }

  public write(alert: AlertRecord): void {
    if (this.stream) {
      this.stream.write(JSON.stringify(alert) + "\n");
    }
  }

  public close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.stream) {
        this.stream.end(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
