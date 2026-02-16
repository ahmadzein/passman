import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { VaultStatus } from "../types";

interface McpStatus {
  installed: boolean;
  path: string | null;
}

interface SettingsProps {
  status: VaultStatus;
}

export function Settings({ status }: SettingsProps) {
  const [mcpStatus, setMcpStatus] = useState<McpStatus | null>(null);
  const [installing, setInstalling] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);

  useEffect(() => {
    invoke<McpStatus>("check_mcp_installed").then(setMcpStatus);
  }, []);

  const handleInstall = async () => {
    setInstalling(true);
    setInstallError(null);
    try {
      const path = await invoke<string>("install_mcp_server");
      setMcpStatus({ installed: true, path });
    } catch (e: any) {
      setInstallError(e?.message || "Installation failed");
    } finally {
      setInstalling(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h2>Settings</h2>
      </div>

      <div className="settings-section">
        <h3>Vault Status</h3>
        <div className="settings-row">
          <span className="label">Status</span>
          <span className="value" style={{ color: status.unlocked ? "var(--success)" : "var(--danger)" }}>
            {status.unlocked ? "Unlocked" : "Locked"}
          </span>
        </div>
        <div className="settings-row">
          <span className="label">Credentials</span>
          <span className="value">{status.credential_count}</span>
        </div>
        <div className="settings-row">
          <span className="label">Environments</span>
          <span className="value">
            {status.environments.length > 0
              ? status.environments.join(", ")
              : "\u2014"}
          </span>
        </div>
      </div>

      <div className="settings-section">
        <h3>Vault Path</h3>
        <div className="settings-row">
          <span className="label">Location</span>
          <span className="value">~/.passman/vault.json</span>
        </div>
        <div className="settings-row">
          <span className="label">Audit Log</span>
          <span className="value">~/.passman/audit.jsonl</span>
        </div>
      </div>

      <div className="settings-section">
        <h3>MCP Server</h3>

        {mcpStatus === null ? (
          <p style={{ fontSize: 13, color: "var(--text-muted)" }}>Checking...</p>
        ) : mcpStatus.installed ? (
          <>
            <div className="settings-row">
              <span className="label">Status</span>
              <span className="value" style={{ color: "var(--success)" }}>Installed</span>
            </div>
            <div className="settings-row">
              <span className="label">Binary</span>
              <span className="value">{mcpStatus.path}</span>
            </div>
          </>
        ) : (
          <div
            style={{
              background: "rgba(251, 191, 36, 0.08)",
              border: "1px solid rgba(251, 191, 36, 0.25)",
              borderRadius: "var(--radius)",
              padding: 16,
              marginBottom: 12,
            }}
          >
            <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: 0, marginBottom: 12 }}>
              MCP server not found. Install it to use Passman with AI clients like Claude Code, Cursor, and VS Code Copilot.
            </p>
            <button
              onClick={handleInstall}
              disabled={installing}
              style={{
                background: "var(--accent)",
                color: "#fff",
                border: "none",
                borderRadius: "var(--radius)",
                padding: "10px 20px",
                fontSize: 13,
                fontWeight: 600,
                cursor: installing ? "wait" : "pointer",
                opacity: installing ? 0.7 : 1,
              }}
            >
              {installing ? "Installing..." : "Install MCP Server"}
            </button>
            {installError && (
              <p style={{ fontSize: 12, color: "var(--danger)", marginTop: 8, margin: 0 }}>
                {installError}
              </p>
            )}
          </div>
        )}

        <div className="settings-row">
          <span className="label">Transport</span>
          <span className="value">stdio</span>
        </div>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 12 }}>
          To use with Claude Code or other MCP clients, add the server to your
          MCP configuration:
        </p>
        <pre
          style={{
            background: "var(--bg-tertiary)",
            padding: 12,
            borderRadius: "var(--radius)",
            fontSize: 12,
            marginTop: 8,
            overflow: "auto",
            color: "var(--text-secondary)",
          }}
        >
{`{
  "mcpServers": {
    "passman": {
      "command": "${mcpStatus?.path || "passman-mcp-server"}",
      "args": []
    }
  }
}`}
        </pre>
      </div>

      <div className="settings-section">
        <h3>Security</h3>
        <div className="settings-row">
          <span className="label">Encryption</span>
          <span className="value">AES-256-GCM</span>
        </div>
        <div className="settings-row">
          <span className="label">Key Derivation</span>
          <span className="value">Argon2id (64 MiB, 3 iter)</span>
        </div>
        <div className="settings-row">
          <span className="label">Per-credential</span>
          <span className="value">Unique nonces</span>
        </div>
      </div>
    </div>
  );
}
