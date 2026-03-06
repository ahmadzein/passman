use crate::policy::PolicyEngine;
use crate::tools;
use passman_vault::Vault;
use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};

/// The Passman MCP server. Holds the vault handle and policy engine.
#[derive(Clone)]
pub struct PassmanServer {
    pub vault: Vault,
    pub policy: std::sync::Arc<PolicyEngine>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl PassmanServer {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            policy: std::sync::Arc::new(PolicyEngine::new()),
            tool_router: Self::tool_router(),
        }
    }

    // ── Vault Management ─────────────────────────────────────

    #[tool(description = "Unlock the vault with the master password. MUST be called before any other tool. Creates a new vault if none exists. Returns credential count on success.")]
    async fn vault_unlock(
        &self,
        Parameters(params): Parameters<tools::vault::VaultUnlockRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::vault::vault_unlock(self, params).await
    }

    #[tool(description = "Lock the vault, clearing the encryption key from memory.")]
    async fn vault_lock(&self) -> Result<CallToolResult, McpError> {
        tools::vault::vault_lock(self).await
    }

    #[tool(description = "Check vault status: locked/unlocked, credential count, environments.")]
    async fn vault_status(&self) -> Result<CallToolResult, McpError> {
        tools::vault::vault_status(self).await
    }

    // ── Credential Discovery ─────────────────────────────────

    #[tool(description = "List credentials with optional filters by kind, environment, or tag. Returns id, name, kind, environment, tags for each credential. Never returns secret values. Use this to find credential UUIDs for proxy tools.")]
    async fn credential_list(
        &self,
        Parameters(params): Parameters<tools::discovery::CredentialListRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::discovery::credential_list(self, params).await
    }

    #[tool(description = "Search credentials by name, tags, or notes. Never returns secret values.")]
    async fn credential_search(
        &self,
        Parameters(params): Parameters<tools::discovery::CredentialSearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::discovery::credential_search(self, params).await
    }

    #[tool(description = "Get detailed metadata for a credential (name, kind, environment, tags, notes). Never returns secret values.")]
    async fn credential_info(
        &self,
        Parameters(params): Parameters<tools::discovery::CredentialInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::discovery::credential_info(self, params).await
    }

    // ── Credential Storage ───────────────────────────────────

    #[tool(description = "Store a NEW credential in the vault. ALWAYS creates a new entry with a new UUID. To modify an existing credential, use credential_update instead. Supports kinds: password, api_token, ssh_key, ssh_password, database_connection, certificate, smtp_account, custom. The 'secret' field structure depends on the kind (see server instructions for field details).")]
    async fn credential_store(
        &self,
        Parameters(params): Parameters<tools::storage::CredentialStoreRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::storage::credential_store(self, params).await
    }

    #[tool(description = "Update an EXISTING credential by UUID. Pass only the fields you want to change; omitted fields keep their current values. Use this instead of credential_store when modifying credentials to avoid creating duplicates. The secret field structure must match the credential's kind.")]
    async fn credential_update(
        &self,
        Parameters(params): Parameters<tools::storage::CredentialUpdateRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::storage::credential_update(self, params).await
    }

    #[tool(description = "Delete a credential from the vault. Requires confirm=true.")]
    async fn credential_delete(
        &self,
        Parameters(params): Parameters<tools::storage::CredentialDeleteRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::storage::credential_delete(self, params).await
    }

    // ── Protocol Proxies ─────────────────────────────────────

    #[tool(description = "Make an HTTP request using a stored credential for authentication. Supports credential types: api_token (Bearer/custom header), password (Basic auth), certificate (mTLS), and custom (with auth_strategy: basic/bearer/headers). The credential's secret is injected as auth headers and NEVER exposed to you. Response body and headers are sanitized to remove any secret values.")]
    async fn http_request(
        &self,
        Parameters(params): Parameters<tools::http::HttpRequestParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::http::http_request(self, params).await
    }

    #[tool(description = "Execute a command on a remote host via SSH using a stored ssh_key or ssh_password credential. Host and port are read from the credential. Output is sanitized. Commands with no output for 120s are timed out. For background processes, redirect ALL file descriptors: nohup cmd > /tmp/out.log 2>&1 < /dev/null & disown")]
    async fn ssh_exec(
        &self,
        Parameters(params): Parameters<tools::ssh::SshExecParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ssh::ssh_exec(self, params).await
    }

    #[tool(description = "Execute a SQL query using a stored database_connection credential. Connects using the credential's driver/host/port/database. Returns columns, rows, and rows_affected. Results are sanitized. Supports parameterized queries via the params array. Policy can enforce read-only mode.")]
    async fn sql_query(
        &self,
        Parameters(params): Parameters<tools::sql::SqlQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::sql::sql_query(self, params).await
    }

    #[tool(description = "Send an email using a stored smtp_account credential. Supports to, cc, bcc recipients. Email body is plain text. The sender address is taken from the credential's username. Recipients can be restricted by policy.")]
    async fn send_email(
        &self,
        Parameters(params): Parameters<tools::smtp::SendEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::smtp::send_email(self, params).await
    }

    // ── Audit ────────────────────────────────────────────────

    #[tool(description = "View the audit log of proxy operations. Filter by credential_id, limit, or time range.")]
    async fn audit_log(
        &self,
        Parameters(params): Parameters<AuditLogParams>,
    ) -> Result<CallToolResult, McpError> {
        let credential_id = params
            .credential_id
            .map(|id| {
                id.parse::<uuid::Uuid>()
                    .map_err(|_| McpError::invalid_params("invalid UUID", None))
            })
            .transpose()?;

        let since = params
            .since
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .map_err(|_| McpError::invalid_params("invalid datetime (use RFC3339)", None))
            })
            .transpose()?;

        match self
            .vault
            .read_audit(credential_id, params.limit.map(|l| l as usize), since)
            .await
        {
            Ok(entries) => {
                let items: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "timestamp": e.timestamp.to_rfc3339(),
                            "credential_id": e.credential_id.map(|id| id.to_string()),
                            "credential_name": e.credential_name,
                            "action": e.action,
                            "tool": e.tool,
                            "success": e.success,
                            "details": e.details,
                        })
                    })
                    .collect();

                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string(&items).unwrap(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditLogParams {
    #[schemars(description = "Filter by credential UUID")]
    pub credential_id: Option<String>,
    #[schemars(description = "Maximum number of entries to return")]
    pub limit: Option<u32>,
    #[schemars(description = "Only return entries after this RFC3339 datetime")]
    pub since: Option<String>,
}

#[tool_handler]
impl ServerHandler for PassmanServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Passman is a secure credential proxy. It stores credentials in an encrypted vault \
                 and lets you USE them via proxy tools (HTTP, SSH, SQL, SMTP) without ever seeing \
                 the raw secrets.\n\n\
                 ## Getting Started\n\
                 1. Call vault_unlock with the master password\n\
                 2. Call credential_list to see available credentials\n\
                 3. Use proxy tools (http_request, ssh_exec, sql_query, send_email) with credential UUIDs\n\n\
                 ## Credential Types & Secret Fields\n\
                 - password: {username, password, url?}\n\
                 - api_token: {token, header_name?, prefix?} - header_name defaults to 'Authorization', prefix to 'Bearer '\n\
                 - ssh_key: {username, host, port?, private_key, passphrase?}\n\
                 - ssh_password: {username, host, port?, password}\n\
                 - database_connection: {driver, host, port?, database, username, password} - driver: postgres/mysql/sqlite\n\
                 - certificate: {cert_pem, key_pem, ca_pem?} - for mTLS\n\
                 - smtp_account: {host, port?, username, password, encryption?} - encryption: tls/start_tls/none\n\
                 - custom: {fields: {key: value, ...}} - see Custom Auth below\n\n\
                 ## Custom Auth Strategies (for http_request)\n\
                 Store a 'custom' credential with an 'auth_strategy' field in the fields map:\n\
                 - auth_strategy: 'basic' - HTTP Basic Auth using client_id/username + client_secret/password fields\n\
                 - auth_strategy: 'bearer' - Bearer token using 'token' field\n\
                 - auth_strategy: 'headers' (default) - each field becomes a custom HTTP header\n\
                 Example for OAuth: kind=custom, secret={client_id: '...', client_secret: '...', auth_strategy: 'basic'}\n\n\
                 ## Updating vs Storing Credentials\n\
                 - credential_store: ALWAYS creates a NEW credential with a new UUID\n\
                 - credential_update: modifies an EXISTING credential by UUID - use this for edits\n\
                 Never use credential_store to update - it will create duplicates.\n\n\
                 ## SSH Tips\n\
                 - Background processes (nohup, &) will HANG unless you redirect ALL file descriptors: \
                   nohup <cmd> > /tmp/out.log 2>&1 < /dev/null & disown\n\
                 - Commands with no output for 120s are timed out automatically.\n\
                 - To check a background process: pgrep -f <pattern> or cat /tmp/out.log"
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
