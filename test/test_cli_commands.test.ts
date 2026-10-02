/**
 * PassiveSentinel - CLI Integration Test Suite
 * Executes end-to-end testing of CLI commands using Node.js test runner.
 */

import { test, describe } from "node:test";
import * as assert from "node:assert";
import { execSync } from "child_process";
import * as path from "path";
import * as fs from "fs";

const CLI_BIN = path.resolve(process.cwd(), "bin/passivesentinel");
const FIXTURES_DIR = path.resolve(process.cwd(), "test/golden/fixtures");
const GOLDEN_FLOWS = path.resolve(FIXTURES_DIR, "golden_flows.csv");

describe("PassiveSentinel CLI Integration Tests", () => {
  test("CLI help output exits 0", () => {
    const out = execSync(`node "${CLI_BIN}" --help`).toString();
    assert.match(out, /Passive streaming network threat intelligence CLI/);
    assert.match(out, /analyze-flow/);
    assert.match(out, /benchmark/);
    assert.match(out, /doctor/);
  });

  test("model info prints valid bundle specifications", () => {
    const out = execSync(`node "${CLI_BIN}" model info`).toString();
    assert.match(out, /Bundle Version:\s+0\.1\.0/);
    assert.match(out, /Cryptographic Integrity:\s+VERIFIED/);
    assert.match(out, /benign/);
    assert.match(out, /beaconing/);
  });

  test("model verify validates SHA-256 signatures", () => {
    const out = execSync(`node "${CLI_BIN}" model verify`).toString();
    assert.match(out, /Model bundle SHA-256 integrity verified/);
  });

  test("doctor diagnostics pass all enclave checks", () => {
    const out = execSync(`node "${CLI_BIN}" doctor`).toString();
    assert.match(out, /ALL DOCTOR CHECKS PASSED/);
  });

  test("analyze-flow executes detection and produces alerts", () => {
    const tmpAlerts = path.resolve(process.cwd(), "test/test_alerts_output.jsonl");
    if (fs.existsSync(tmpAlerts)) fs.unlinkSync(tmpAlerts);

    const out = execSync(`node "${CLI_BIN}" analyze-flow "${GOLDEN_FLOWS}" --output "${tmpAlerts}"`).toString();
    assert.match(out, /PASSIVESENTINEL RUN SUMMARY/);
    assert.match(out, /recon_scan|encrypted_malware/);
    assert.ok(fs.existsSync(tmpAlerts), "Alerts output file was not created");

    const lines = fs.readFileSync(tmpAlerts, "utf-8").trim().split("\n");
    assert.ok(lines.length > 0, "Alerts file is empty");

    const firstAlert = JSON.parse(lines[0]);
    assert.strictEqual(firstAlert.schema_version, "1.0");
    assert.ok(firstAlert.alert_id.startsWith("a-"));
    assert.ok(firstAlert.confidence >= 0.0 && firstAlert.confidence <= 1.0);
    assert.ok(["low", "medium", "high", "critical"].includes(firstAlert.severity.level));

    if (fs.existsSync(tmpAlerts)) fs.unlinkSync(tmpAlerts);
  });
});
