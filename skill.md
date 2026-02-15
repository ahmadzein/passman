# Passman - Secure Credential Proxy MCP Server

Passman is an encrypted credential vault and proxy. It stores credentials locally and lets AI agents **USE** them via proxy tools (HTTP, SSH, SQL, SMTP) without ever seeing the raw secrets. Credentials are encrypted with AES-256-GCM and derived via Argon2id.

---

## Installation

```bash
# One command — downloads pre-built binary, no Rust required
curl -fsSL https://raw.githubusercontent.com/ahmadzein/passman/main/install.sh | bash

# Then add to your AI client:
claude mcp add --transport stdio passman -- ~/.local/bin/passman-mcp-server
```

Or add to `.mcp.json` in your project:
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

---

## Quick Start

1. **Unlock the vault** with `vault_unlock` (creates a new vault on first use)
2. **Store credentials** with `credential_store`
3. **Use credentials** via proxy tools: `http_request`, `ssh_exec`, `sql_query`, `send_email`
4. **Lock when done** with `vault_lock`

---

## Tools Reference (14 Tools)

### Vault Management

#### `vault_unlock`
Unlock the vault with master password. Creates a new vault if none exists.
```
Input:  { password: string }
Output: { success: bool, credential_count: int }
```

#### `vault_lock`
Lock the vault and zero the encryption key from memory.
```
Input:  {}
Output: { success: bool }
```

#### `vault_status`
Check if vault exists and its lock state.
```
Input:  {}
Output: { exists: bool, locked: bool, credential_count?: int, environments?: [string] }
```

---

### Credential Discovery

These tools **never return secret values** -- only metadata.

#### `credential_list`
List credentials with optional filters.
```
Input:  { kind?: string, environment?: string, tag?: string }
Output: [{ id, name, kind, environment, tags }]
```

**Filterable kinds:** `password`, `api_token`, `ssh_key`, `ssh_password`, `database_connection`, `certificate`, `smtp_account`, `custom`

**Filterable environments:** `local`, `development`, `staging`, `production`

#### `credential_search`
Search credentials by name, tags, or notes.
```
Input:  { query: string }
Output: [{ id, name, kind, environment }]
```

#### `credential_info`
Get detailed metadata for a credential (no secrets).
```
Input:  { id: string }
Output: { id, name, kind, environment, tags, notes, created_at, updated_at }
```

---

### Credential Storage

#### `credential_store`
Store a new credential in the vault. See "Credential Kinds" section for secret formats.
```
Input:  { name: string, kind: string, environment: string, secret: object, tags?: [string], notes?: string }
Output: { id: string, name: string }
```

#### `credential_delete`
Delete a credential. Requires `confirm: true` as a safety measure.
```
Input:  { id: string, confirm: true }
Output: { success: bool }
```

---

### Protocol Proxies

These tools execute operations using stored credentials. The AI **never sees** the raw credential -- Passman injects it server-side and sanitizes all output.

#### `http_request`
Make an authenticated HTTP request.
```
Input:  { credential_id: string, method: string, url: string, headers?: object, body?: string }
Output: { status: int, headers: object, body: string }
```

- **method:** GET, POST, PUT, PATCH, DELETE, HEAD
- **ApiToken credentials:** Injects `Authorization: Bearer {token}` (customizable header/prefix)
- **Password credentials:** Injects `Authorization: Basic {base64(user:pass)}`
- **Certificate credentials:** mTLS with PEM cert/key

#### `ssh_exec`
Execute a command on a remote server via SSH.
```
Input:  { credential_id: string, command: string }
Output: { exit_code: int, stdout: string, stderr: string }
```

- **SshKey credentials:** Public key authentication (with optional passphrase)
- **SshPassword credentials:** Password authentication

#### `sql_query`
Execute a SQL query against a database.
```
Input:  { credential_id: string, query: string, params?: [any] }
Output: { columns: [string], rows: [[any]], rows_affected: int }
```

- **Supported drivers:** PostgreSQL, MySQL, SQLite
- **Read-only enforcement:** Policy can block INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE

#### `send_email`
Send an email via SMTP.
```
Input:  { credential_id: string, to: [string], subject: string, body: string, cc?: [string], bcc?: [string] }
Output: { success: bool, message_id?: string }
```

- **Encryption modes:** None, StartTLS, TLS
- **Recipient restrictions:** Policy can limit allowed recipient patterns

---

### Audit

#### `audit_log`
View the audit trail of all credential operations.
```
Input:  { credential_id?: string, limit?: int, since?: string }
Output: [{ timestamp, credential_id, credential_name, action, tool, success, details }]
```

- **since:** RFC 3339 datetime (e.g. `2026-02-15T00:00:00Z`)
- **Tracked actions:** VaultUnlock, VaultLock, CredentialList, CredentialSearch, CredentialInfo, CredentialStore, CredentialDelete, HttpRequest, SshExec, SqlQuery, SendEmail, AuditView

---

## Credential Kinds

### Password
```json
{ "username": "admin", "password": "s3cret", "url": "https://example.com" }
```
`url` is optional. Used for HTTP Basic auth via `http_request`.

### API Token
```json
{ "token": "ghp_abc123", "header_name": "Authorization", "prefix": "Bearer" }
```
`header_name` defaults to `Authorization`, `prefix` defaults to `Bearer`.

### SSH Key
```json
{ "username": "deploy", "host": "10.0.1.5", "port": 22, "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...", "passphrase": "optional" }
```
`port` defaults to 22. `passphrase` is optional.

### SSH Password
```json
{ "username": "admin", "host": "10.0.1.5", "port": 22, "password": "s3cret" }
```
`port` defaults to 22.

### Database Connection
```json
{ "driver": "postgres", "host": "db.example.com", "port": 5432, "database": "mydb", "username": "app", "password": "s3cret", "params": {} }
```
**Drivers:** `postgres`, `mysql`, `sqlite`. `params` is an optional map of connection string parameters.

### Certificate
```json
{ "cert_pem": "-----BEGIN CERTIFICATE-----\n...", "key_pem": "-----BEGIN PRIVATE KEY-----\n...", "ca_pem": "-----BEGIN CERTIFICATE-----\n..." }
```
`ca_pem` is optional. Used for mTLS via `http_request`.

### SMTP Account
```json
{ "host": "smtp.gmail.com", "port": 587, "username": "user@gmail.com", "password": "app-password", "encryption": "start_tls" }
```
**Encryption:** `none`, `start_tls`, `tls`

### Custom
```json
{ "field1": "value1", "field2": "value2" }
```
Arbitrary key-value pairs. All values are treated as secrets and sanitized.

---

## Environments

Credentials are categorized by environment:

| Environment | Use Case |
|-------------|----------|
| `local` | Local development, personal machines |
| `development` | Dev/test servers |
| `staging` | Pre-production, QA |
| `production` | Live systems |

---

## Policy Engine

Per-credential rules that restrict how credentials can be used:

| Rule | Description | Example |
|------|-------------|---------|
| `allowed_tools` | Which proxy tools can use this credential | `["http_request", "ssh_exec"]` |
| `http_url_patterns` | Allowed URL patterns (glob with `*`) | `["https://api.github.com/*"]` |
| `ssh_command_patterns` | Allowed SSH commands (glob with `*`) | `["ls *", "cat *", "grep *"]` |
| `sql_allow_write` | Allow write queries (default: false) | `false` = SELECT only |
| `smtp_allowed_recipients` | Allowed email patterns | `["*@company.com"]` |
| `rate_limit` | Max requests per time window | `{ "max_requests": 100, "window_secs": 3600 }` |

---

## Output Sanitization

All proxy responses are automatically scrubbed of credential values before returning to the AI. The sanitizer checks multiple encodings:

1. **Raw string** -- direct match
2. **Base64** -- standard and URL-safe
3. **URL-encoded** -- percent-encoded
4. **Hex-encoded** -- lower and uppercase
5. Secrets shorter than 4 characters are skipped to avoid false positives

**Applied to:** HTTP response body/headers, SSH stdout/stderr, SQL result rows.

---

## Security Model

| Layer | Protection |
|-------|-----------|
| No raw secret access | No MCP tool ever returns credential secret values |
| Output sanitization | All proxy responses scrubbed across 6 encoding variants |
| Policy engine | Per-credential allow/deny rules, URL/command patterns, read-only SQL |
| Rate limiting | Sliding window per credential prevents abuse |
| Audit trail | Every operation logged with timestamp, credential, tool, success/failure |
| Memory safety | Encryption key zeroed on drop via `zeroize` crate |

---

## Common Workflows

### Store and use an API key
```
1. credential_store { name: "GitHub Token", kind: "api_token", environment: "production", secret: { token: "ghp_..." } }
2. http_request { credential_id: "<id>", method: "GET", url: "https://api.github.com/user/repos" }
```

### SSH into a server
```
1. credential_store { name: "Prod Web Server", kind: "ssh_password", environment: "production", secret: { username: "deploy", host: "10.0.1.5", password: "..." } }
2. ssh_exec { credential_id: "<id>", command: "systemctl status nginx" }
```

### Query a database
```
1. credential_store { name: "Analytics DB", kind: "database_connection", environment: "staging", secret: { driver: "postgres", host: "db.staging.com", port: 5432, database: "analytics", username: "reader", password: "..." } }
2. sql_query { credential_id: "<id>", query: "SELECT count(*) FROM events WHERE date > $1", params: ["2026-01-01"] }
```

### Send an email
```
1. credential_store { name: "Notifications SMTP", kind: "smtp_account", environment: "production", secret: { host: "smtp.gmail.com", port: 587, username: "notifications@company.com", password: "...", encryption: "start_tls" } }
2. send_email { credential_id: "<id>", to: ["team@company.com"], subject: "Deploy Complete", body: "v2.1.0 deployed to production." }
```

### Review audit trail
```
1. audit_log { limit: 20 }                                           -- last 20 operations
2. audit_log { credential_id: "<id>" }                               -- operations for one credential
3. audit_log { since: "2026-02-15T00:00:00Z" }                      -- operations since a date
```

---

## File Locations

| File | Purpose |
|------|---------|
| `~/.passman/vault.json` | Encrypted credential vault |
| `~/.passman/audit.jsonl` | Append-only audit log |

---

## Encryption Details

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** Argon2id (64 MiB memory, 3 iterations, 4 parallelism)
- **Nonces:** Unique random per credential
- **Metadata:** Stored in plaintext (searchable). Secrets encrypted individually.
- **Key lifecycle:** Derived on unlock, held in memory, zeroed on lock/drop
