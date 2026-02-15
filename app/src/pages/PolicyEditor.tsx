import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import type { CredentialMeta, PolicyRule } from "../types";

const ALL_TOOLS = [
  "http_request",
  "ssh_exec",
  "sql_query",
  "send_email",
];

export function PolicyEditor() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [meta, setMeta] = useState<CredentialMeta | null>(null);
  const [allowedTools, setAllowedTools] = useState<string[]>([...ALL_TOOLS]);
  const [httpPatterns, setHttpPatterns] = useState<string[]>([]);
  const [sshPatterns, setSshPatterns] = useState<string[]>([]);
  const [sqlAllowWrite, setSqlAllowWrite] = useState(false);
  const [smtpRecipients, setSmtpRecipients] = useState<string[]>([]);
  const [rateLimitEnabled, setRateLimitEnabled] = useState(false);
  const [maxRequests, setMaxRequests] = useState("60");
  const [windowSecs, setWindowSecs] = useState("3600");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    (async () => {
      try {
        const info = await invoke<CredentialMeta>("credential_info", { id });
        setMeta(info);

        const policy = await invoke<PolicyRule | null>("policy_get", {
          credentialId: id,
        });
        if (policy) {
          setAllowedTools(policy.allowed_tools);
          setHttpPatterns(policy.http_url_patterns);
          setSshPatterns(policy.ssh_command_patterns);
          setSqlAllowWrite(policy.sql_allow_write);
          setSmtpRecipients(policy.smtp_allowed_recipients);
          if (policy.rate_limit) {
            setRateLimitEnabled(true);
            setMaxRequests(String(policy.rate_limit.max_requests));
            setWindowSecs(String(policy.rate_limit.window_secs));
          }
        }
      } catch (err) {
        console.error("Failed to load policy:", err);
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  const toggleTool = (tool: string) => {
    setAllowedTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    );
  };

  if (loading) {
    return (
      <div className="app-loading">
        <div className="spinner" />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <h2>Policy: {meta?.name || id}</h2>
      </div>

      <div className="policy-form">
        <div className="policy-section">
          <h3>Allowed Tools</h3>
          <div className="checkbox-group">
            {ALL_TOOLS.map((tool) => (
              <label key={tool}>
                <input
                  type="checkbox"
                  checked={allowedTools.includes(tool)}
                  onChange={() => toggleTool(tool)}
                />
                {tool}
              </label>
            ))}
          </div>
        </div>

        <div className="policy-section">
          <h3>HTTP URL Patterns</h3>
          <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            Glob patterns for allowed URLs (e.g., https://api.github.com/*)
          </p>
          <PatternList
            patterns={httpPatterns}
            onChange={setHttpPatterns}
            placeholder="https://api.example.com/*"
          />
        </div>

        <div className="policy-section">
          <h3>SSH Command Patterns</h3>
          <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            Glob patterns for allowed commands (e.g., ls *, cat *)
          </p>
          <PatternList
            patterns={sshPatterns}
            onChange={setSshPatterns}
            placeholder="ls *"
          />
        </div>

        <div className="policy-section">
          <h3>SQL Access</h3>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={sqlAllowWrite}
              onChange={(e) => setSqlAllowWrite(e.target.checked)}
              style={{ accentColor: "var(--accent)" }}
            />
            <span style={{ fontSize: 14, color: "var(--text-secondary)" }}>
              Allow write operations (INSERT, UPDATE, DELETE)
            </span>
          </label>
        </div>

        <div className="policy-section">
          <h3>SMTP Allowed Recipients</h3>
          <PatternList
            patterns={smtpRecipients}
            onChange={setSmtpRecipients}
            placeholder="*@company.com"
          />
        </div>

        <div className="policy-section">
          <h3>Rate Limiting</h3>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", marginBottom: 12 }}>
            <input
              type="checkbox"
              checked={rateLimitEnabled}
              onChange={(e) => setRateLimitEnabled(e.target.checked)}
              style={{ accentColor: "var(--accent)" }}
            />
            <span style={{ fontSize: 14, color: "var(--text-secondary)" }}>
              Enable rate limiting
            </span>
          </label>
          {rateLimitEnabled && (
            <div style={{ display: "flex", gap: 12 }}>
              <div className="form-group" style={{ flex: 1 }}>
                <label>Max Requests</label>
                <input
                  type="number"
                  value={maxRequests}
                  onChange={(e) => setMaxRequests(e.target.value)}
                />
              </div>
              <div className="form-group" style={{ flex: 1 }}>
                <label>Window (seconds)</label>
                <input
                  type="number"
                  value={windowSecs}
                  onChange={(e) => setWindowSecs(e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        {error && <div className="form-error">{error}</div>}
        {saved && <div style={{ color: "var(--success)", fontSize: 13, marginBottom: 8 }}>Policy saved successfully.</div>}

        <div className="editor-actions">
          <button
            className="btn btn-primary"
            disabled={saving}
            onClick={async () => {
              setSaving(true);
              setError("");
              setSaved(false);
              try {
                await invoke("policy_save", {
                  input: {
                    credentialId: id,
                    allowedTools,
                    httpUrlPatterns: httpPatterns,
                    sshCommandPatterns: sshPatterns,
                    sqlAllowWrite,
                    smtpAllowedRecipients: smtpRecipients,
                    rateLimit: rateLimitEnabled
                      ? { maxRequests: parseInt(maxRequests, 10), windowSecs: parseInt(windowSecs, 10) }
                      : null,
                  },
                });
                setSaved(true);
              } catch (err: any) {
                setError(typeof err === "string" ? err : err?.message || "Failed to save policy");
              } finally {
                setSaving(false);
              }
            }}
          >
            {saving ? "Saving..." : "Save Policy"}
          </button>
          <button className="btn btn-secondary" onClick={() => navigate(`/credential/${id}`)}>
            Back to Credential
          </button>
        </div>
      </div>
    </div>
  );
}

function PatternList({
  patterns,
  onChange,
  placeholder,
}: {
  patterns: string[];
  onChange: (p: string[]) => void;
  placeholder: string;
}) {
  const [newPattern, setNewPattern] = useState("");

  const addPattern = () => {
    if (newPattern.trim()) {
      onChange([...patterns, newPattern.trim()]);
      setNewPattern("");
    }
  };

  return (
    <div className="pattern-list">
      {patterns.map((p, i) => (
        <div key={i} className="pattern-item">
          <input
            type="text"
            value={p}
            onChange={(e) => {
              const updated = [...patterns];
              updated[i] = e.target.value;
              onChange(updated);
            }}
            style={{
              padding: "6px 10px",
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: "var(--text-primary)",
              fontSize: 13,
              fontFamily: "monospace",
            }}
          />
          <button onClick={() => onChange(patterns.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
        <input
          type="text"
          value={newPattern}
          onChange={(e) => setNewPattern(e.target.value)}
          placeholder={placeholder}
          onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addPattern())}
          style={{
            flex: 1,
            padding: "6px 10px",
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            color: "var(--text-primary)",
            fontSize: 13,
          }}
        />
        <button type="button" className="btn btn-secondary btn-sm" onClick={addPattern}>
          Add
        </button>
      </div>
    </div>
  );
}
