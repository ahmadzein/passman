<div align="center">

# Passman

### Secure Credential Proxy for AI Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io/)
[![Version](https://img.shields.io/badge/version-0.0.1-green.svg)](https://github.com/ahmadzein/passman/releases/tag/v0.0.1)

**Let AI agents *use* your credentials without ever *seeing* them.**

SSH into servers. Query databases. Call APIs. Send emails.
All without exposing a single password, key, or token to the LLM.

[Website](https://ahmadzein.github.io/passman) | [Documentation](https://ahmadzein.github.io/passman) | [Changelog](CHANGELOG.md)

</div>

---

## The Problem

Every MCP server that handles credentials today either **exposes secrets to the AI** or is **limited to a single protocol**. There is no unified, secure, multi-protocol credential proxy.

## The Solution

Passman is an **encrypted local vault** + **credential proxy** that sits between AI agents and your infrastructure. The AI references credentials by name. Passman injects them server-side. The AI gets results back -- with secrets scrubbed from every response.

```
  AI Agent                    Passman                     Your Infrastructure
 ┌─────────┐               ┌──────────┐               ┌─────────────────────┐
 │ "Query   │  credential   │ Decrypt  │  inject auth  │                     │
 │  prod-db │ ────by ID───> │ + Proxy  │ ────────────> │  PostgreSQL / SSH   │
 │  for     │               │ + Scrub  │               │  API / SMTP Server  │
 │  users"  │ <──sanitized─ │  output  │ <──response── │                     │
 └─────────┘    response    └──────────┘               └─────────────────────┘
                                │
                  AI never sees │ passwords, keys,
                                │ tokens, or secrets
```

---

## Features

### Multi-Protocol Proxy
| Protocol | Tool | What It Does |
|----------|------|-------------|
| **HTTP** | `http_request` | REST API calls with Bearer tokens, Basic auth, or mTLS certificates |
| **SSH** | `ssh_exec` | Remote command execution with SSH keys or passwords |
| **SQL** | `sql_query` | Database queries on PostgreSQL, MySQL, SQLite |
| **SMTP** | `send_email` | Send emails via any SMTP server |

### Encrypted Vault
- **AES-256-GCM** authenticated encryption per credential
- **Argon2id** key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- Unique random nonces per credential
- Encryption key zeroed from memory on lock via `zeroize`

### 8 Credential Types
| Type | Use Case |
|------|----------|
| Password | Web logins, Basic auth |
| API Token | Bearer tokens, API keys |
| SSH Key | Public key authentication |
| SSH Password | Password-based SSH |
| Database Connection | PostgreSQL, MySQL, SQLite |
| Certificate | mTLS, client certificates |
| SMTP Account | Email sending |
| Custom | Any key-value secret |

### Output Sanitization
Every proxy response is scrubbed of credential values across **6 encoding variants** before reaching the AI:
- Raw string, Base64 (standard + URL-safe), URL-encoded, Hex (lower + upper)

### Policy Engine
Per-credential rules to restrict what the AI can do:
- **URL patterns** -- `https://api.github.com/*`
- **SSH command patterns** -- `ls *`, `cat *` (block dangerous commands)
- **SQL read-only mode** -- blocks INSERT, UPDATE, DELETE, DROP
- **SMTP recipient restrictions** -- `*@company.com`
- **Rate limiting** -- sliding window per credential

### Environment Categories
Organize credentials by: `local` | `development` | `staging` | `production`

### Audit Trail
Every operation logged to `~/.passman/audit.jsonl`:
- Timestamp, credential used, tool called, success/failure, command details

### Desktop GUI
Tauri v2 + React app for visual credential management:
- Unlock screen with vault creation
- Credential browser with filtering
- Type-specific credential editors
- Policy configuration
- Audit log viewer

---

## Security Model

```
┌─────────────────────────────────────────────────────────┐
│                    6 LAYERS OF DEFENSE                   │
├─────────────────────────────────────────────────────────┤
│ 1. NO RAW SECRET ACCESS   No tool returns secret values │
│ 2. OUTPUT SANITIZATION     6 encoding variants scrubbed │
│ 3. POLICY ENGINE          Per-credential allow/deny     │
│ 4. RATE LIMITING          Sliding window per credential │
│ 5. AUDIT TRAIL            Every operation logged        │
│ 6. MEMORY SAFETY          zeroize-on-drop for all keys  │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Install

```bash
# One command — downloads pre-built binary, no Rust required
curl -fsSL https://raw.githubusercontent.com/ahmadzein/passman/main/install.sh | bash
```

Or build from source:
```bash
git clone https://github.com/ahmadzein/passman.git
cd passman
cargo build --release -p passman-mcp-server
cp target/release/passman-mcp-server ~/.local/bin/
```

> **AI-readable reference:** See [`skill.md`](skill.md) for the complete tool reference optimized for AI agents.

### Configure Your AI Client

<details>
<summary><strong>Claude Code</strong></summary>

```bash
claude mcp add --transport stdio passman -- ~/.local/bin/passman-mcp-server
```

Or add to `.mcp.json`:
```json
{
  "mcpServers": {
    "passman": {
      "command": "~/.local/bin/passman-mcp-server",
      "args": [],
      "transport": "stdio"
    }
  }
}
```
</details>

<details>
<summary><strong>Cursor</strong></summary>

In Cursor settings > MCP Servers:
```json
{
  "mcpServers": {
    "passman": {
      "command": "~/.local/bin/passman-mcp-server"
    }
  }
}
```
</details>

<details>
<summary><strong>VS Code (Copilot)</strong></summary>

In `.vscode/mcp.json`:
```json
{
  "servers": {
    "passman": {
      "type": "stdio",
      "command": "~/.local/bin/passman-mcp-server"
    }
  }
}
```
</details>

<details>
<summary><strong>Claude Desktop</strong></summary>

In `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "passman": {
      "command": "~/.local/bin/passman-mcp-server",
      "args": []
    }
  }
}
```
</details>

<details>
<summary><strong>Windsurf</strong></summary>

In MCP configuration:
```json
{
  "mcpServers": {
    "passman": {
      "command": "~/.local/bin/passman-mcp-server",
      "args": []
    }
  }
}
```
</details>

### Use It

```
You:  "Unlock my vault"
AI:   vault_unlock({password: "..."}) → Vault unlocked. 5 credentials.

You:  "List my credentials"
AI:   credential_list() → [{name: "GitHub Token", kind: "api_token"}, ...]

You:  "Use my GitHub token to check my repos"
AI:   http_request({credential_id: "abc-123", method: "GET", url: "https://api.github.com/user/repos"})
      → {status: 200, body: [{name: "my-project", ...}]}
      // Token was injected server-side. AI never saw it.

You:  "SSH into prod and check nginx status"
AI:   ssh_exec({credential_id: "def-456", command: "systemctl status nginx"})
      → {exit_code: 0, stdout: "● nginx.service - active (running)..."}
      // Password/key never exposed.
```

---

## 14 MCP Tools

| Category | Tool | Description |
|----------|------|-------------|
| **Vault** | `vault_unlock` | Unlock vault with master password |
| | `vault_lock` | Lock vault, zero key from memory |
| | `vault_status` | Check vault state |
| **Discovery** | `credential_list` | List credentials (filterable) |
| | `credential_search` | Search by name, tags, notes |
| | `credential_info` | Get credential metadata (no secret) |
| **Storage** | `credential_store` | Store a new credential |
| | `credential_delete` | Delete a credential |
| **Proxies** | `http_request` | Authenticated HTTP request |
| | `ssh_exec` | SSH command execution |
| | `sql_query` | Database query (Postgres/MySQL/SQLite) |
| | `send_email` | Send email via SMTP |
| **Audit** | `audit_log` | View usage history |

---

## Architecture

```
passman/
├── crates/
│   ├── passman-types/       # Shared types, enums, traits
│   ├── passman-vault/       # Encrypted vault: crypto, CRUD, audit
│   ├── passman-proxy/       # Protocol proxies + output sanitizer
│   └── passman-mcp/         # MCP server (rmcp), 14 tools, policy engine
├── bins/
│   └── passman-mcp-server/  # Standalone MCP binary (stdio transport)
├── app/                     # Tauri v2 + React desktop app
└── skill.md                 # AI-readable feature reference
```

### Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust |
| MCP SDK | rmcp 0.15+ |
| Encryption | aes-gcm + argon2 |
| HTTP Proxy | reqwest |
| SSH Proxy | russh |
| SQL Proxy | sqlx (any driver) |
| SMTP Proxy | lettre |
| Desktop GUI | Tauri v2 + React |
| Memory Safety | zeroize + secrecy |

---

## Desktop GUI

A full-featured desktop app for visual credential management, built with Tauri v2 + React. Shares the same vault as the MCP server.

### Download

| Platform | Download |
|----------|----------|
| macOS (Apple Silicon) | [Passman_x.x.x_aarch64.dmg](https://github.com/ahmadzein/passman/releases/latest) |
| macOS (Intel) | [Passman_x.x.x_x64.dmg](https://github.com/ahmadzein/passman/releases/latest) |
| Windows | [Passman_x.x.x_x64-setup.exe](https://github.com/ahmadzein/passman/releases/latest) |
| Linux (AppImage) | [Passman_x.x.x_amd64.AppImage](https://github.com/ahmadzein/passman/releases/latest) |
| Linux (deb) | [Passman_x.x.x_amd64.deb](https://github.com/ahmadzein/passman/releases/latest) |

Or install via the CLI installer:
```bash
curl -fsSL https://raw.githubusercontent.com/ahmadzein/passman/main/install.sh | GUI=1 bash
```

### Build from Source

```bash
cd app
npm install
npm run tauri dev     # Development
npm run tauri build   # Production build
```

### Screens

Unlock | Vault Browser | Credential Editor | Policy Editor | Audit Log | Settings

> **Note:** The GUI and MCP server share the same vault at `~/.passman/vault.json`. Changes in one are immediately visible in the other.

---

## Running Tests

```bash
cargo test --workspace         # All unit tests
```

---

## File Locations

| File | Purpose |
|------|---------|
| `~/.passman/vault.json` | Encrypted credential vault |
| `~/.passman/audit.jsonl` | Append-only audit log |

---

## Why Passman?

| | Passman | Janee | mcp-secrets-vault | 1Password `op run` | Google Toolbox |
|---|---|---|---|---|---|
| **Protocols** | HTTP + SSH + SQL + SMTP | HTTP only | HTTP (GET/POST only) | Env vars only | SQL only |
| **Credential proxy** | Full proxy | HTTP proxy | HTTP proxy | Env injection | SQL proxy |
| **Encrypted vault** | AES-256-GCM | AES-256-GCM | Env vars only | 1Password vault | Config file |
| **Output sanitization** | 6 encodings | Basic (8+ chars) | Basic | stdout masking | None |
| **Self-hosted** | Yes (local-first) | Yes | Yes | Requires 1Password | Google Cloud bias |
| **Desktop GUI** | Tauri + React | No | No | 1Password app | No |
| **Open source** | MIT | MIT | MIT | Proprietary | Apache 2.0 |
| **Policy engine** | Per-credential rules | Per-capability | Per-secret domain | None | DB permissions |
| **Cost** | Free | Free | Free | $3-8/mo | Free |

---

## Contributing

Contributions welcome! Please open an issue first to discuss what you'd like to change.

```bash
# Development setup
git clone https://github.com/ahmadzein/passman.git
cd passman
cargo build
cargo test --workspace
```

---

## License

[MIT](LICENSE) - Use it, fork it, build on it.

---

<div align="center">

**Built with Rust. Secured by design. Open source forever.**

[Report Bug](https://github.com/ahmadzein/passman/issues) | [Request Feature](https://github.com/ahmadzein/passman/issues)

</div>
