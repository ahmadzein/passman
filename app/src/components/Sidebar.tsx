import { NavLink } from "react-router-dom";
import type { VaultStatus } from "../types";

interface SidebarProps {
  status: VaultStatus;
  onLock: () => void;
}

export function Sidebar({ status, onLock }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <h1>Passman</h1>
        <div className="vault-info">
          {status.credential_count} credential{status.credential_count !== 1 ? "s" : ""}
        </div>
      </div>

      <nav className="sidebar-nav">
        <NavLink to="/" end>
          <span>&#128274;</span> Vault
        </NavLink>
        <NavLink to="/credential/new">
          <span>&#43;</span> New Credential
        </NavLink>
        <NavLink to="/audit">
          <span>&#128220;</span> Audit Log
        </NavLink>
        <NavLink to="/settings">
          <span>&#9881;</span> Settings
        </NavLink>
      </nav>

      <div className="sidebar-footer">
        <button onClick={onLock}>Lock Vault</button>
      </div>
    </aside>
  );
}
