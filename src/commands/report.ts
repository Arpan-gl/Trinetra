/**
 * PassiveSentinel - `report` command handler
 * Generates human-readable Markdown or HTML executive summaries from alerts JSONL.
 */

import chalk from "chalk";
import * as fs from "fs";
import * as readline from "readline";
import * as path from "path";
import { AlertRecord } from "../engine/protocol";

export async function handleReport(filePath: string, options: {
  output?: string;
  format?: string;
}): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`[Error] Alerts file not found: ${filePath}`));
    process.exit(4);
  }

  const alerts: AlertRecord[] = [];
  const fileStream = fs.createReadStream(filePath);
  const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed) {
      try {
        alerts.push(JSON.parse(trimmed));
      } catch (e) {}
    }
  }

  if (alerts.length === 0) {
    console.log(chalk.yellow("No alerts found in file."));
    return;
  }

  // Aggregate stats
  const severityCounts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const classCounts: Record<string, number> = {};
  const entityCounts: Record<string, number> = {};

  for (const a of alerts) {
    severityCounts[a.severity.level] = (severityCounts[a.severity.level] || 0) + 1;
    classCounts[a.threat_class] = (classCounts[a.threat_class] || 0) + 1;
    const entity = a.flow_id.split("|")[0] || "unknown";
    entityCounts[entity] = (entityCounts[entity] || 0) + 1;
  }

  const topEntities = Object.entries(entityCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Generate Markdown report
  const now = new Date().toISOString();
  let md = `# 🛡️ PassiveSentinel Forensic Incident Report\n\n`;
  md += `**Generated UTC:** ${now}  \n`;
  md += `**Source File:** \`${path.basename(filePath)}\`  \n`;
  md += `**Total Incidents Detected:** ${alerts.length}  \n\n`;

  md += `## 1. Incident Severity Breakdown\n\n`;
  md += `| Severity Level | Count | Action Required |\n`;
  md += `|---|---|---|\n`;
  md += `| **Critical** | ${severityCounts.critical || 0} | Immediate containment / upstream BGP drop |\n`;
  md += `| **High** | ${severityCounts.high || 0} | Priority analyst triage & endpoint isolation |\n`;
  md += `| **Medium** | ${severityCounts.medium || 0} | Host review & telemetry inspection |\n`;
  md += `| **Low** | ${severityCounts.low || 0} | Logged for statistical baselining |\n\n`;

  md += `## 2. Threat Taxonomy Distribution\n\n`;
  md += `| Threat Family | Incident Count | Share |\n`;
  md += `|---|---|---|\n`;
  for (const [cls, count] of Object.entries(classCounts)) {
    const share = ((count / alerts.length) * 100).toFixed(1);
    md += `| \`${cls}\` | **${count}** | ${share}% |\n`;
  }

  md += `\n## 3. Top Suspect Entities\n\n`;
  md += `| Entity Key | Alerts Triggered |\n`;
  md += `|---|---|\n`;
  for (const [ent, count] of topEntities) {
    md += `| \`${ent}\` | **${count}** |\n`;
  }

  md += `\n## 4. Recent Incident Timeline\n\n`;
  md += `| Time (UTC) | Class | Severity | Flow ID | Recommended Action |\n`;
  md += `|---|---|---|---|---|\n`;
  for (const a of alerts.slice(0, 20)) {
    md += `| ${a.timestamp} | \`${a.threat_class}\` | **${a.severity.level.toUpperCase()}** (${a.severity.score}) | \`${a.flow_id}\` | ${a.recommended_action} |\n`;
  }

  const outPath = options.output || path.resolve("passivesentinel_report.md");
  fs.writeFileSync(outPath, md, "utf-8");

  console.log(chalk.bold.green(`✔ [SUCCESS] Forensic report generated successfully!`));
  console.log(`Report written to: ${chalk.cyan(outPath)}`);
}
