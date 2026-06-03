#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { scanMcpConfig, severityRank, type Finding, type ScanResult, type Severity } from "./index.js";

interface CliOptions {
  files: string[];
  format: "text" | "json";
  failOn: Severity;
  help: boolean;
  version: boolean;
}

const DEFAULT_IGNORES = new Set([".git", "dist", "node_modules"]);

export function run(argv: string[]): number {
  const options = parseArgs(argv);

  if (options.help) {
    console.log(helpText());
    return 0;
  }

  if (options.version) {
    console.log("mcp-security-linter 1.0.0");
    return 0;
  }

  if (options.files.length === 0) {
    console.error("No files or directories provided.\n");
    console.error(helpText());
    return 2;
  }

  const result = scanFiles(options.files);
  if (options.format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(formatText(result));
  }

  if (result.errors.length > 0) {
    return 2;
  }

  return result.findings.some(
    (finding) => severityRank[finding.severity] >= severityRank[options.failOn]
  )
    ? 1
    : 0;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    files: [],
    format: "text",
    failOn: "high",
    help: false,
    version: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }

    if (arg === "--version" || arg === "-v") {
      options.version = true;
      continue;
    }

    if (arg === "--format") {
      options.format = parseFormat(argv[++index]);
      continue;
    }

    if (arg.startsWith("--format=")) {
      options.format = parseFormat(arg.slice("--format=".length));
      continue;
    }

    if (arg === "--fail-on") {
      options.failOn = parseSeverity(argv[++index]);
      continue;
    }

    if (arg.startsWith("--fail-on=")) {
      options.failOn = parseSeverity(arg.slice("--fail-on=".length));
      continue;
    }

    options.files.push(arg);
  }

  return options;
}

function parseFormat(value: string | undefined): "text" | "json" {
  if (value === "text" || value === "json") {
    return value;
  }
  throw new Error("--format must be text or json");
}

function parseSeverity(value: string | undefined): Severity {
  if (value === "low" || value === "medium" || value === "high") {
    return value;
  }
  throw new Error("--fail-on must be low, medium, or high");
}

function scanFiles(inputs: string[]): ScanResult {
  const files = inputs.flatMap((input) => expandInput(input));
  const result: ScanResult = {
    filesScanned: 0,
    findings: [],
    errors: []
  };

  for (const file of files) {
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
      result.findings.push(...scanMcpConfig(file, parsed));
      result.filesScanned += 1;
    } catch (error) {
      result.errors.push({
        file,
        message: error instanceof Error ? error.message : String(error)
      });
    }
  }

  result.findings.sort(sortFindings);
  return result;
}

function expandInput(input: string): string[] {
  const absolute = resolve(input);
  const stats = statSync(absolute);

  if (stats.isFile()) {
    return [absolute];
  }

  if (!stats.isDirectory()) {
    return [];
  }

  return collectJsonFiles(absolute);
}

function collectJsonFiles(directory: string): string[] {
  const entries = readdirSync(directory, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    if (DEFAULT_IGNORES.has(entry.name)) {
      continue;
    }

    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectJsonFiles(fullPath));
      continue;
    }

    if (entry.isFile() && extname(entry.name).toLowerCase() === ".json") {
      files.push(fullPath);
    }
  }

  return files;
}

function formatText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`Scanned ${result.filesScanned} JSON file(s).`);

  if (result.errors.length > 0) {
    lines.push("");
    lines.push("Errors:");
    result.errors.forEach((error) => {
      lines.push(`  ${error.file}: ${error.message}`);
    });
  }

  if (result.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  lines.push("");
  lines.push(`Findings: ${result.findings.length}`);
  result.findings.forEach((finding) => {
    const server = finding.server ? ` server=${finding.server}` : "";
    const evidence = finding.evidence ? ` evidence=${finding.evidence}` : "";
    lines.push(
      `  [${finding.severity}] ${finding.ruleId}${server} ${finding.file} ${finding.path}`
    );
    lines.push(`      ${finding.message}${evidence}`);
  });

  return lines.join("\n");
}

function sortFindings(a: Finding, b: Finding): number {
  return (
    severityRank[b.severity] - severityRank[a.severity] ||
    a.file.localeCompare(b.file) ||
    a.path.localeCompare(b.path)
  );
}

function helpText(): string {
  return `Usage:
  mcp-security-linter <file-or-directory...> [--format text|json] [--fail-on low|medium|high]
  mcpsec <file-or-directory...>

Examples:
  mcpsec ~/.cursor/mcp.json
  mcpsec . --fail-on medium
  mcpsec mcp.json --format json
`;
}

try {
  process.exitCode = run(process.argv.slice(2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 2;
}
