# Changelog

All notable changes to Passman will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-02-15

### Added

#### Core Vault
- AES-256-GCM encrypted local vault at `~/.passman/vault.json`
- Argon2id key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- Per-credential encryption with unique random nonces
- File-level locking (`fd-lock`) for concurrent GUI + MCP access
- Memory safety with `zeroize`-on-drop for all secret material

#### Credential Types (8)
- Password (username/password/url)
- API Token (token/header_name/prefix)
- SSH Key (username/host/port/private_key/passphrase)
- SSH Password (username/host/port/password)
- Database Connection (driver/host/port/database/username/password)
- Certificate (cert_pem/key_pem/ca_pem)
- SMTP Account (host/port/username/password/encryption)
- Custom (arbitrary key-value pairs)

#### MCP Server (14 Tools)
- `vault_unlock` / `vault_lock` / `vault_status` -- vault lifecycle
- `credential_list` / `credential_search` / `credential_info` -- discovery (never returns secrets)
- `credential_store` / `credential_delete` -- credential CRUD
- `http_request` -- authenticated HTTP proxy (Bearer, Basic, mTLS)
- `ssh_exec` -- SSH command execution proxy (key + password auth)
- `sql_query` -- database query proxy (PostgreSQL, MySQL, SQLite)
- `send_email` -- SMTP email proxy (None/StartTLS/TLS)
- `audit_log` -- view operation history

#### Output Sanitization
- Multi-encoding secret scrubbing: raw, base64, URL-encoded, hex (lower + upper)
- Applied to HTTP responses, SSH stdout/stderr, SQL result rows
- Minimum 4-character threshold to avoid false positives

#### Policy Engine
- Per-credential tool allowlists
- HTTP URL pattern matching (glob with `*`)
- SSH command pattern matching (glob with `*`)
- SQL read-only enforcement (blocks INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/TRUNCATE)
- SMTP recipient pattern restrictions
- Sliding window rate limiting per credential

#### Audit Trail
- Append-only JSONL log at `~/.passman/audit.jsonl`
- Logs: timestamp, credential_id, credential_name, action, tool, success, details
- Filterable by credential_id, limit, and time range

#### Environment Categories
- Local, Development, Staging, Production support
- Tag-based organization

#### Desktop GUI (Tauri v2 + React)
- Unlock screen with vault creation flow
- Vault browser with kind/environment/tag filtering
- Type-specific credential editors for all 8 kinds
- Policy editor
- Audit log viewer
- Settings page

#### Documentation
- Marketing website (GitHub Pages)
- AI skill reference (`skill.md`)
- MCP client configuration guides (Claude Code, Cursor, VS Code, Claude Desktop, Windsurf)

#### Compatibility
- Claude Code (stdio transport)
- Cursor
- VS Code Copilot
- Claude Desktop
- Windsurf
- Any MCP client supporting stdio transport

[0.0.1]: https://github.com/ahmadzein/passman/releases/tag/v0.0.1
