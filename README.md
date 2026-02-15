# Passman

**Secure Credential Proxy MCP Server + Desktop GUI**

Passman lets AI agents *use* your credentials (SSH, SQL, HTTP APIs, SMTP) without ever *seeing* them. Credentials are encrypted locally with AES-256-GCM, and a proxy pattern ensures raw secrets never appear in LLM context.

## Features

- **14 MCP tools** — vault management, credential discovery, and protocol proxies
- **Proxy pattern** — credentials injected server-side, never returned to the AI
- **Multi-protocol** — HTTP, SSH, SQL (Postgres/MySQL/SQLite), SMTP
- **Output sanitization** — multi-encoding scrub (raw, base64, URL-encoded, hex)
- **Per-credential policies** — URL patterns, command allow-lists, SQL read-only, rate limits
- **Encrypted vault** — AES-256-GCM with Argon2id key derivation (64 MiB, 3 iterations)
- **Desktop GUI** — Tauri v2 + React for credential management
- **Audit trail** — every proxy call logged with timestamp, credential, tool, success/failure
- **File-watcher sync** — GUI and MCP server share the vault file, auto-reload on changes

## Architecture

```
passman/
├── crates/
│   ├── passman-types/       # Shared types (CredentialKind, Secret, Policy, etc.)
│   ├── passman-vault/       # Encrypted vault: crypto, CRUD, audit, file watcher
│   ├── passman-proxy/       # Protocol proxies + output sanitizer
│   └── passman-mcp/         # MCP server (rmcp), 14 tools, policy engine
├── bins/
│   └── passman-mcp-server/  # Standalone MCP binary (stdio transport)
├── app/                     # Tauri v2 + React desktop app
└── tests/                   # Integration tests
```

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- [Node.js](https://nodejs.org/) 18+
- System dependencies for Tauri (see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/))

### Build the MCP Server

```bash
cargo build --release -p passman-mcp-server
```

The binary is at `target/release/passman-mcp-server`.

```bash
# Verify it works
./target/release/passman-mcp-server --version
# passman-mcp-server 0.1.0
```

### Build the Desktop App

```bash
cd app
npm install
npm run tauri build
```

### Run in Development

```bash
# Terminal 1: Run the desktop app
cd app
npm run tauri dev

# The MCP server runs separately via your AI client config
```

## MCP Client Configuration

### Claude Code

Add to your MCP settings (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "passman": {
      "command": "/path/to/passman-mcp-server",
      "args": []
    }
  }
}
```

### Cursor

In Cursor settings, add an MCP server:

```json
{
  "mcpServers": {
    "passman": {
      "command": "/path/to/passman-mcp-server"
    }
  }
}
```

### VS Code (Copilot)

In `.vscode/mcp.json`:

```json
{
  "servers": {
    "passman": {
      "type": "stdio",
      "command": "/path/to/passman-mcp-server"
    }
  }
}
```

## MCP Tools

### Vault Management

| Tool | Description |
|------|-------------|
| `vault_unlock` | Unlock the vault with master password |
| `vault_lock` | Lock the vault, zero key from memory |
| `vault_status` | Check lock state, credential count, environments |

### Credential Discovery (never returns secrets)

| Tool | Description |
|------|-------------|
| `credential_list` | List credentials with optional kind/environment/tag filters |
| `credential_search` | Search credentials by name, tags, notes |
| `credential_info` | Get metadata for a credential (no secret) |

### Credential Storage

| Tool | Description |
|------|-------------|
| `credential_store` | Store a new credential (7 types supported) |
| `credential_delete` | Delete a credential (requires confirmation) |

### Protocol Proxies (credential never exposed to AI)

| Tool | Description |
|------|-------------|
| `http_request` | Make HTTP request with stored API token/password |
| `ssh_exec` | Execute SSH command with stored key/password |
| `sql_query` | Run SQL query with stored database credentials |
| `send_email` | Send email with stored SMTP credentials |

### Audit

| Tool | Description |
|------|-------------|
| `audit_log` | View proxy usage history |

## Credential Types

| Type | Fields |
|------|--------|
| Password | username, password, url |
| API Token | token, header_name, prefix |
| SSH Key | username, host, port, private_key, passphrase |
| Database | driver, host, port, database, username, password |
| Certificate | cert_pem, key_pem, ca_pem |
| SMTP Account | host, port, username, password, encryption |
| Custom | arbitrary key-value fields |

## Security Model

### 6 Layers of Protection

1. **No raw secret access** — No MCP tool returns credential secret values
2. **Output sanitization** — All proxy responses scrubbed of secret values across multiple encodings (raw, base64, URL-encoded, hex uppercase/lowercase)
3. **Policy engine** — Per-credential allow/deny rules, URL patterns, command patterns
4. **Rate limiting** — Sliding window per credential
5. **Audit trail** — Every proxy call logged
6. **Memory safety** — Encryption key uses `zeroize`-on-drop wrapper

### Cryptography

| Component | Algorithm |
|-----------|-----------|
| Encryption | AES-256-GCM (per-credential unique nonces) |
| Key Derivation | Argon2id (64 MiB memory, 3 iterations, 4 parallelism) |
| Key Storage | In-memory only, zeroed on lock/drop |

### Vault File

- Location: `~/.passman/vault.json`
- Metadata stored in plaintext (searchable)
- Each credential's secret independently encrypted
- Audit log: `~/.passman/audit.jsonl` (append-only JSONL)

## Example Usage with AI

```
User: "List my credentials"
AI calls: credential_list() → [{name: "GitHub Token", kind: "api_token", ...}]

User: "Use my GitHub token to check my repos"
AI calls: http_request({
  credential_id: "abc-123",
  method: "GET",
  url: "https://api.github.com/user/repos"
}) → {status: 200, body: [{name: "my-repo", ...}]}
// The AI never sees the token — it was injected server-side
```

## Running Tests

```bash
# All unit tests (28 tests)
cargo test --workspace

# Integration tests (vault lifecycle + cross-process reload)
cargo test -p passman-vault --test lifecycle
```

## Project Status

- [x] Phase 1: Vault foundation (crypto, storage, CRUD, audit)
- [x] Phase 2: MCP server (14 tools via rmcp)
- [x] Phase 3: Protocol proxies (HTTP, SSH, SQL, SMTP) + sanitizer
- [x] Phase 4: Desktop GUI (Tauri v2 + React, 6 screens)
- [x] Phase 5: Integration (file-watcher, policy CRUD, CLI flags, tests)
- [x] Phase 6: Documentation

## License

MIT
