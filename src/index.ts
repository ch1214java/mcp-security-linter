export type Severity = "low" | "medium" | "high";

export interface Finding {
  file: string;
  path: string;
  ruleId: string;
  severity: Severity;
  message: string;
  evidence?: string;
  server?: string;
}

export interface ScanError {
  file: string;
  message: string;
}

export interface ScanResult {
  filesScanned: number;
  findings: Finding[];
  errors: ScanError[];
}

const SECRET_KEY_PATTERN =
  /(api[_-]?key|token|secret|password|passwd|private[_-]?key|access[_-]?key|auth[_-]?token|credential)/i;

const SAFE_SECRET_REFERENCE_PATTERN =
  /^(\$\{[A-Z0-9_]+\}|%[A-Z0-9_]+%|\$[A-Z0-9_]+)$/i;

const SHELL_COMMANDS = new Set([
  "bash",
  "cmd",
  "cmd.exe",
  "fish",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
  "sh",
  "wsl",
  "zsh"
]);

const SHELL_EXEC_FLAGS = new Set([
  "-c",
  "/c",
  "-command",
  "-encodedcommand",
  "-encodedarguments"
]);

const DANGEROUS_SHELL_PATTERNS = [
  /\brm\s+-rf\b/i,
  /\bdel\s+\/[fsq]/i,
  /\brmdir\s+\/s\b/i,
  /\bformat\s+[a-z]:/i,
  /\binvoke-expression\b/i,
  /\biex\b/i,
  /\bcurl\b.*\|\s*(bash|sh|pwsh|powershell)\b/i,
  /\bwget\b.*\|\s*(bash|sh|pwsh|powershell)\b/i,
  /\bchmod\s+777\b/i
];

const BROAD_FS_PATTERNS = [
  /^\/$/,
  /^[a-z]:\\$/i,
  /^~$/,
  /^\$HOME$/i,
  /^%USERPROFILE%$/i,
  /^--?(allow-all|allow-all-paths|allow-write|allow-root)$/i,
  /^--?(root|dir|directory|workspace|path)=(\/|[a-z]:\\|~|\$HOME|%USERPROFILE%)/i
];

export const severityRank: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3
};

export function scanMcpConfig(file: string, value: unknown): Finding[] {
  const findings: Finding[] = [];
  const servers = getMcpServers(value);

  if (servers.size === 0) {
    findings.push({
      file,
      path: "$",
      ruleId: "no-mcp-servers",
      severity: "low",
      message: "No mcpServers object was found. Confirm this is an MCP config before relying on the scan."
    });
  }

  for (const [serverName, serverValue] of servers) {
    inspectServer(file, serverName, serverValue, findings);
  }

  inspectObject(file, "$", value, findings);
  return dedupeFindings(findings);
}

function getMcpServers(value: unknown): Map<string, unknown> {
  const servers = new Map<string, unknown>();

  if (!isRecord(value)) {
    return servers;
  }

  const direct = value.mcpServers;
  if (isRecord(direct)) {
    for (const [name, server] of Object.entries(direct)) {
      servers.set(name, server);
    }
  }

  const nested = value.servers;
  if (isRecord(nested)) {
    for (const [name, server] of Object.entries(nested)) {
      servers.set(name, server);
    }
  }

  return servers;
}

function inspectServer(
  file: string,
  server: string,
  value: unknown,
  findings: Finding[]
): void {
  if (!isRecord(value)) {
    findings.push({
      file,
      server,
      path: `$.mcpServers.${server}`,
      ruleId: "invalid-server",
      severity: "medium",
      message: "MCP server entry is not an object."
    });
    return;
  }

  const command = stringValue(value.command);
  const args = Array.isArray(value.args)
    ? value.args.map((item) => String(item))
    : [];

  if (command && SHELL_COMMANDS.has(normalizeCommand(command))) {
    const flag = args.find((arg) => SHELL_EXEC_FLAGS.has(arg.toLowerCase()));
    findings.push({
      file,
      server,
      path: `$.mcpServers.${server}.command`,
      ruleId: "shell-wrapper",
      severity: flag ? "medium" : "low",
      message: flag
        ? "Server starts through a shell execution flag. Review the command string carefully."
        : "Server starts through a shell wrapper. Prefer executing the server binary directly.",
      evidence: [command, ...args].join(" ")
    });
  }

  const commandLine = [command, ...args].filter(Boolean).join(" ");
  if (DANGEROUS_SHELL_PATTERNS.some((pattern) => pattern.test(commandLine))) {
    findings.push({
      file,
      server,
      path: `$.mcpServers.${server}.args`,
      ruleId: "dangerous-shell-command",
      severity: "high",
      message: "Command line contains a destructive or remote-code-execution pattern.",
      evidence: commandLine
    });
  }

  args.forEach((arg, index) => {
    if (isBroadFilesystemAccess(arg)) {
      findings.push({
        file,
        server,
        path: `$.mcpServers.${server}.args[${index}]`,
        ruleId: "broad-filesystem-access",
        severity: "medium",
        message: "Argument appears to grant access to a broad filesystem scope.",
        evidence: arg
      });
    }
  });

  if (isRecord(value.env)) {
    for (const [key, envValue] of Object.entries(value.env)) {
      inspectSecretLikeValue({
        file,
        server,
        path: `$.mcpServers.${server}.env.${key}`,
        key,
        value: envValue,
        findings
      });

      if (typeof envValue === "string" && isBroadFilesystemAccess(envValue)) {
        findings.push({
          file,
          server,
          path: `$.mcpServers.${server}.env.${key}`,
          ruleId: "broad-filesystem-access",
          severity: "medium",
          message: "Environment value appears to grant access to a broad filesystem scope.",
          evidence: envValue
        });
      }
    }
  }
}

function inspectObject(
  file: string,
  path: string,
  value: unknown,
  findings: Finding[]
): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspectObject(file, `${path}[${index}]`, item, findings));
    return;
  }

  if (!isRecord(value)) {
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const nestedPath = `${path}.${key}`;
    inspectSecretLikeValue({
      file,
      path: nestedPath,
      key,
      value: nested,
      findings
    });
    inspectObject(file, nestedPath, nested, findings);
  }
}

function inspectSecretLikeValue(input: {
  file: string;
  path: string;
  key: string;
  value: unknown;
  findings: Finding[];
  server?: string;
}): void {
  if (!SECRET_KEY_PATTERN.test(input.key) || typeof input.value !== "string") {
    return;
  }

  const trimmed = input.value.trim();
  if (!trimmed || SAFE_SECRET_REFERENCE_PATTERN.test(trimmed)) {
    return;
  }

  input.findings.push({
    file: input.file,
    server: input.server,
    path: input.path,
    ruleId: "inline-secret",
    severity: "high",
    message: "Secret-like key stores an inline value. Move the value to a secret manager or environment variable reference.",
    evidence: redact(trimmed)
  });
}

function isBroadFilesystemAccess(value: string): boolean {
  const trimmed = value.trim();
  return BROAD_FS_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function normalizeCommand(command: string): string {
  return command.replace(/^.*[\\/]/, "").toLowerCase();
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function redact(value: string): string {
  if (value.length <= 8) {
    return "<redacted>";
  }
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = [
      finding.file,
      finding.path,
      finding.ruleId,
      finding.severity,
      finding.evidence
    ].join("|");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
