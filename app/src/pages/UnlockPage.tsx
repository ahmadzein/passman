import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface UnlockPageProps {
  onUnlocked: () => void;
}

export function UnlockPage({ onUnlocked }: UnlockPageProps) {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isNewVault, setIsNewVault] = useState(false);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    invoke<boolean>("vault_exists").then((exists) => {
      setIsNewVault(!exists);
      setLoading(false);
    });
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (isNewVault) {
      if (password.length < 8) {
        setError("Password must be at least 8 characters");
        return;
      }
      if (password !== confirmPassword) {
        setError("Passwords do not match");
        return;
      }
    }

    setSubmitting(true);
    try {
      if (isNewVault) {
        await invoke("vault_create", { password });
      } else {
        await invoke("vault_unlock", { password });
      }
      onUnlocked();
    } catch (err: any) {
      const msg = typeof err === "string" ? err : err?.message || "Failed to unlock vault";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="unlock-page">
        <div className="spinner" />
      </div>
    );
  }

  return (
    <div className="unlock-page">
      <div className="unlock-card">
        <h1>Passman</h1>
        <p className="subtitle">
          {isNewVault
            ? "Create a master password to secure your vault"
            : "Enter your master password to unlock"}
        </p>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Master Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter master password"
              autoFocus
              disabled={submitting}
            />
          </div>

          {isNewVault && (
            <div className="form-group">
              <label>Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm master password"
                disabled={submitting}
              />
            </div>
          )}

          {error && <div className="form-error">{error}</div>}

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", marginTop: 16 }}
            disabled={submitting || !password}
          >
            {submitting
              ? "Please wait..."
              : isNewVault
              ? "Create Vault"
              : "Unlock"}
          </button>
        </form>
      </div>
    </div>
  );
}
