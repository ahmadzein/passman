import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import type {
  CredentialMeta,
  CredentialSecret,
  CredentialKind,
} from "../types";
import { CREDENTIAL_KINDS, ENVIRONMENTS } from "../types";

interface CredentialEditorProps {
  onSaved: () => void;
}

export function CredentialEditor({ onSaved }: CredentialEditorProps) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isNew = !id;

  const [name, setName] = useState("");
  const [kind, setKind] = useState<CredentialKind>("password");
  const [environment, setEnvironment] = useState("local");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [secret, setSecret] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    (async () => {
      try {
        const meta = await invoke<CredentialMeta>("credential_info", { id });
        setName(meta.name);
        setKind(meta.kind);
        setEnvironment(
          typeof meta.environment === "string"
            ? meta.environment
            : meta.environment.custom
        );
        setTags(meta.tags.join(", "));
        setNotes(meta.notes || "");

        const sec = await invoke<CredentialSecret>("credential_get_secret", { id });
        const flat: Record<string, string> = {};
        Object.entries(sec).forEach(([k, v]) => {
          if (k !== "type" && typeof v === "string") flat[k] = v;
          if (k !== "type" && typeof v === "number") flat[k] = String(v);
        });
        setSecret(flat);
      } catch (err: any) {
        setError(typeof err === "string" ? err : err?.message || "Failed to load");
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  const buildSecretPayload = (): object => {
    switch (kind) {
      case "password":
        return {
          type: "password",
          username: secret.username || "",
          password: secret.password || "",
          url: secret.url || undefined,
        };
      case "api_token":
        return {
          type: "api_token",
          token: secret.token || "",
          header_name: secret.header_name || undefined,
          prefix: secret.prefix || undefined,
        };
      case "ssh_key":
        return {
          type: "ssh_key",
          username: secret.username || "",
          host: secret.host || "",
          port: parseInt(secret.port || "22", 10),
          private_key: secret.private_key || "",
          passphrase: secret.passphrase || undefined,
        };
      case "database_connection":
        return {
          type: "database_connection",
          driver: secret.driver || "postgres",
          host: secret.host || "",
          port: parseInt(secret.port || "5432", 10),
          database: secret.database || "",
          username: secret.username || "",
          password: secret.password || "",
        };
      case "certificate":
        return {
          type: "certificate",
          cert_pem: secret.cert_pem || "",
          key_pem: secret.key_pem || "",
          ca_pem: secret.ca_pem || undefined,
        };
      case "smtp_account":
        return {
          type: "smtp_account",
          host: secret.host || "",
          port: parseInt(secret.port || "587", 10),
          username: secret.username || "",
          password: secret.password || "",
          encryption: secret.encryption || "tls",
        };
      case "custom":
        return { type: "custom", fields: secret };
      default:
        return { type: kind, ...secret };
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    setSaving(true);
    setError("");

    try {
      await invoke("credential_store", {
        input: {
          name: name.trim(),
          kind,
          environment,
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          notes: notes.trim() || null,
          secret: buildSecretPayload(),
        },
      });
      onSaved();
      navigate("/");
    } catch (err: any) {
      setError(typeof err === "string" ? err : err?.message || "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  const updateSecret = (key: string, value: string) => {
    setSecret((prev) => ({ ...prev, [key]: value }));
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
        <h2>{isNew ? "New Credential" : `Edit: ${name}`}</h2>
      </div>

      <form className="editor-form" onSubmit={handleSubmit}>
        <div className="editor-section">
          <h3>General</h3>
          <div className="form-group">
            <label>Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., GitHub API Token"
              autoFocus
            />
          </div>
          <div className="form-group">
            <label>Type</label>
            <select
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as CredentialKind);
                setSecret({});
              }}
              disabled={!isNew}
            >
              {CREDENTIAL_KINDS.map((k) => (
                <option key={k.value} value={k.value}>
                  {k.label}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Environment</label>
            <select
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
            >
              {ENVIRONMENTS.map((e) => (
                <option key={e} value={e}>
                  {e.charAt(0).toUpperCase() + e.slice(1)}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Tags (comma-separated)</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="e.g., github, ci, deploy"
            />
          </div>
          <div className="form-group">
            <label>Notes</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Optional notes..."
            />
          </div>
        </div>

        <div className="editor-section">
          <h3>Secret Details</h3>
          <SecretFields kind={kind} secret={secret} onChange={updateSecret} />
        </div>

        {error && <div className="form-error">{error}</div>}

        <div className="editor-actions">
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? "Saving..." : isNew ? "Create Credential" : "Update Credential"}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate("/")}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

function SecretFields({
  kind,
  secret,
  onChange,
}: {
  kind: CredentialKind;
  secret: Record<string, string>;
  onChange: (key: string, value: string) => void;
}) {
  switch (kind) {
    case "password":
      return (
        <>
          <Field label="Username" field="username" secret={secret} onChange={onChange} />
          <Field label="Password" field="password" secret={secret} onChange={onChange} type="password" />
          <Field label="URL" field="url" secret={secret} onChange={onChange} placeholder="https://..." />
        </>
      );
    case "api_token":
      return (
        <>
          <Field label="Token" field="token" secret={secret} onChange={onChange} type="password" />
          <Field label="Header Name" field="header_name" secret={secret} onChange={onChange} placeholder="Authorization" />
          <Field label="Prefix" field="prefix" secret={secret} onChange={onChange} placeholder="Bearer " />
        </>
      );
    case "ssh_key":
      return (
        <>
          <Field label="Username" field="username" secret={secret} onChange={onChange} />
          <Field label="Host" field="host" secret={secret} onChange={onChange} />
          <Field label="Port" field="port" secret={secret} onChange={onChange} placeholder="22" />
          <div className="form-group">
            <label>Private Key</label>
            <textarea
              value={secret.private_key || ""}
              onChange={(e) => onChange("private_key", e.target.value)}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              style={{ minHeight: 120, fontFamily: "monospace" }}
            />
          </div>
          <Field label="Passphrase" field="passphrase" secret={secret} onChange={onChange} type="password" />
        </>
      );
    case "database_connection":
      return (
        <>
          <div className="form-group">
            <label>Driver</label>
            <select
              value={secret.driver || "postgres"}
              onChange={(e) => onChange("driver", e.target.value)}
            >
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
              <option value="sqlite">SQLite</option>
            </select>
          </div>
          <Field label="Host" field="host" secret={secret} onChange={onChange} />
          <Field label="Port" field="port" secret={secret} onChange={onChange} placeholder="5432" />
          <Field label="Database" field="database" secret={secret} onChange={onChange} />
          <Field label="Username" field="username" secret={secret} onChange={onChange} />
          <Field label="Password" field="password" secret={secret} onChange={onChange} type="password" />
        </>
      );
    case "certificate":
      return (
        <>
          <div className="form-group">
            <label>Certificate PEM</label>
            <textarea
              value={secret.cert_pem || ""}
              onChange={(e) => onChange("cert_pem", e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
              style={{ minHeight: 100, fontFamily: "monospace" }}
            />
          </div>
          <div className="form-group">
            <label>Private Key PEM</label>
            <textarea
              value={secret.key_pem || ""}
              onChange={(e) => onChange("key_pem", e.target.value)}
              placeholder="-----BEGIN PRIVATE KEY-----"
              style={{ minHeight: 100, fontFamily: "monospace" }}
            />
          </div>
          <div className="form-group">
            <label>CA PEM (optional)</label>
            <textarea
              value={secret.ca_pem || ""}
              onChange={(e) => onChange("ca_pem", e.target.value)}
              style={{ minHeight: 80, fontFamily: "monospace" }}
            />
          </div>
        </>
      );
    case "smtp_account":
      return (
        <>
          <Field label="Host" field="host" secret={secret} onChange={onChange} placeholder="smtp.gmail.com" />
          <Field label="Port" field="port" secret={secret} onChange={onChange} placeholder="587" />
          <Field label="Username" field="username" secret={secret} onChange={onChange} />
          <Field label="Password" field="password" secret={secret} onChange={onChange} type="password" />
          <div className="form-group">
            <label>Encryption</label>
            <select
              value={secret.encryption || "tls"}
              onChange={(e) => onChange("encryption", e.target.value)}
            >
              <option value="tls">TLS</option>
              <option value="start_tls">STARTTLS</option>
              <option value="none">None</option>
            </select>
          </div>
        </>
      );
    case "custom":
      return <CustomFields secret={secret} onChange={onChange} />;
    default:
      return <p>Unknown credential type</p>;
  }
}

function Field({
  label,
  field,
  secret,
  onChange,
  type = "text",
  placeholder,
}: {
  label: string;
  field: string;
  secret: Record<string, string>;
  onChange: (key: string, value: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <div className="form-group">
      <label>{label}</label>
      <input
        type={type}
        value={secret[field] || ""}
        onChange={(e) => onChange(field, e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

function CustomFields({
  secret,
  onChange,
}: {
  secret: Record<string, string>;
  onChange: (key: string, value: string) => void;
}) {
  const [newKey, setNewKey] = useState("");

  const addField = () => {
    if (newKey.trim() && !(newKey in secret)) {
      onChange(newKey.trim(), "");
      setNewKey("");
    }
  };

  return (
    <>
      {Object.keys(secret).map((key) => (
        <div key={key} className="form-group">
          <label>{key}</label>
          <input
            type="text"
            value={secret[key]}
            onChange={(e) => onChange(key, e.target.value)}
          />
        </div>
      ))}
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <input
          type="text"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="Field name"
          style={{
            flex: 1,
            padding: "8px 12px",
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
            color: "var(--text-primary)",
            fontSize: 14,
          }}
          onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addField())}
        />
        <button type="button" className="btn btn-secondary btn-sm" onClick={addField}>
          Add Field
        </button>
      </div>
    </>
  );
}
