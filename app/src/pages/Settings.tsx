import type { VaultStatus } from "../types";

interface SettingsProps {
  status: VaultStatus;
}

export function Settings({ status }: SettingsProps) {
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
              : "—"}
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
        <div className="settings-row">
          <span className="label">Binary</span>
          <span className="value">passman-mcp-server</span>
        </div>
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
      "command": "passman-mcp-server",
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
