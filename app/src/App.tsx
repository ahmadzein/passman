import { useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { Sidebar } from "./components/Sidebar";
import { UnlockPage } from "./pages/UnlockPage";
import { VaultBrowser } from "./pages/VaultBrowser";
import { CredentialEditor } from "./pages/CredentialEditor";
import { PolicyEditor } from "./pages/PolicyEditor";
import { AuditLog } from "./pages/AuditLog";
import { Settings } from "./pages/Settings";
import type { VaultStatus } from "./types";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshStatus = async () => {
    try {
      const s = await invoke<VaultStatus>("vault_status");
      setStatus(s);
    } catch {
      setStatus({ unlocked: false, credential_count: 0, environments: [] });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshStatus();
  }, []);

  if (loading) {
    return (
      <div className="app-loading">
        <div className="spinner" />
        <p>Loading Passman...</p>
      </div>
    );
  }

  if (!status?.unlocked) {
    return <UnlockPage onUnlocked={refreshStatus} />;
  }

  return (
    <div className="app-layout">
      <Sidebar status={status} onLock={async () => {
        await invoke("vault_lock");
        refreshStatus();
      }} />
      <main className="app-main">
        <Routes>
          <Route path="/" element={<VaultBrowser onRefresh={refreshStatus} />} />
          <Route path="/credential/new" element={<CredentialEditor onSaved={refreshStatus} />} />
          <Route path="/credential/:id" element={<CredentialEditor onSaved={refreshStatus} />} />
          <Route path="/policy/:id" element={<PolicyEditor />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<Settings status={status} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
