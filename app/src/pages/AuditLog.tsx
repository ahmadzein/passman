import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AuditEntry } from "../types";

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(100);

  const fetchEntries = async () => {
    setLoading(true);
    try {
      const results = await invoke<AuditEntry[]>("audit_log", {
        credentialId: null,
        limit,
      });
      setEntries(results);
    } catch (err) {
      console.error("Failed to fetch audit log:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEntries();
  }, [limit]);

  const formatTimestamp = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleString();
  };

  const formatAction = (action: string) => {
    return action
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div>
      <div className="page-header">
        <h2>Audit Log</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            style={{
              padding: "6px 12px",
              background: "var(--bg-secondary)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--text-secondary)",
              fontSize: 13,
            }}
          >
            <option value={50}>Last 50</option>
            <option value={100}>Last 100</option>
            <option value={500}>Last 500</option>
          </select>
          <button className="btn btn-secondary btn-sm" onClick={fetchEntries}>
            Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="app-loading">
          <div className="spinner" />
        </div>
      ) : entries.length === 0 ? (
        <div className="empty-state">
          <p>No audit entries yet</p>
        </div>
      ) : (
        <table className="audit-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Tool</th>
              <th>Credential</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, i) => (
              <tr key={i}>
                <td style={{ whiteSpace: "nowrap" }}>
                  {formatTimestamp(entry.timestamp)}
                </td>
                <td>{formatAction(entry.action)}</td>
                <td>
                  <code style={{ fontSize: 12 }}>{entry.tool}</code>
                </td>
                <td>{entry.credential_name || entry.credential_id || "—"}</td>
                <td className={entry.success ? "audit-success" : "audit-failure"}>
                  {entry.success ? "OK" : "FAIL"}
                </td>
                <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                  {entry.details || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
