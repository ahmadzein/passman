import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import type { CredentialMeta, CredentialKind } from "../types";
import { kindLabel, environmentToString, CREDENTIAL_KINDS, ENVIRONMENTS } from "../types";

interface VaultBrowserProps {
  onRefresh: () => void;
}

export function VaultBrowser({ onRefresh }: VaultBrowserProps) {
  const [credentials, setCredentials] = useState<CredentialMeta[]>([]);
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [envFilter, setEnvFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [deleteConfirm, setDeleteConfirm] = useState<{ id: string; name: string } | null>(null);

  const fetchCredentials = async () => {
    setLoading(true);
    try {
      if (search) {
        const results = await invoke<CredentialMeta[]>("credential_search", {
          query: search,
        });
        setCredentials(results);
      } else {
        const results = await invoke<CredentialMeta[]>("credential_list", {
          kind: kindFilter || null,
          environment: envFilter || null,
          tag: null,
        });
        setCredentials(results);
      }
    } catch (err) {
      console.error("Failed to fetch credentials:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, [kindFilter, envFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCredentials();
  };

  const handleDelete = async (id: string) => {
    setDeleteConfirm(null);
    try {
      await invoke("credential_delete", { id });
      fetchCredentials();
      onRefresh();
    } catch (err) {
      console.error("Failed to delete:", err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h2>Credentials</h2>
        <Link to="/credential/new" className="btn btn-primary btn-sm">
          + New Credential
        </Link>
      </div>

      <form onSubmit={handleSearch} className="search-bar">
        <input
          type="text"
          placeholder="Search credentials..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <button type="submit" className="btn btn-secondary btn-sm">
          Search
        </button>
      </form>

      <div className="filter-bar">
        <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
          <option value="">All Types</option>
          {CREDENTIAL_KINDS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
        <select value={envFilter} onChange={(e) => setEnvFilter(e.target.value)}>
          <option value="">All Environments</option>
          {ENVIRONMENTS.map((e) => (
            <option key={e} value={e}>
              {e.charAt(0).toUpperCase() + e.slice(1)}
            </option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="app-loading">
          <div className="spinner" />
        </div>
      ) : credentials.length === 0 ? (
        <div className="empty-state">
          <p>No credentials found</p>
          <Link to="/credential/new" className="btn btn-primary btn-sm">
            Add your first credential
          </Link>
        </div>
      ) : (
        <div className="cred-list">
          {credentials.map((cred) => (
            <div key={cred.id} className="cred-item">
              <Link to={`/credential/${cred.id}`} className="cred-item-info" style={{ textDecoration: "none", color: "inherit" }}>
                <div className="cred-item-name">{cred.name}</div>
                <div className="cred-item-meta">
                  <span>{environmentToString(cred.environment)}</span>
                  <span>{new Date(cred.updated_at).toLocaleDateString()}</span>
                </div>
              </Link>
              <div className="cred-item-tags">
                {cred.tags.map((tag) => (
                  <span key={tag} className="tag">{tag}</span>
                ))}
              </div>
              <span className="kind-badge">{kindLabel(cred.kind)}</span>
              <button
                className="btn btn-danger btn-sm"
                style={{ marginLeft: 8 }}
                onClick={() => setDeleteConfirm({ id: cred.id, name: cred.name })}
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}

      {deleteConfirm && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => setDeleteConfirm(null)}
        >
          <div
            style={{
              background: "var(--bg-secondary, #1e1e2e)",
              border: "1px solid var(--border, #333)",
              borderRadius: 12,
              padding: 24,
              maxWidth: 400,
              width: "90%",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ margin: "0 0 12px" }}>Delete Credential</h3>
            <p style={{ margin: "0 0 20px", opacity: 0.8 }}>
              Delete <strong>{deleteConfirm.name}</strong>? This cannot be undone.
            </p>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setDeleteConfirm(null)}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => handleDelete(deleteConfirm.id)}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
