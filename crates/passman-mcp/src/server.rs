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

    #[tool(description = "Unlock the vault with the master password. Creates a new vault if none exists.")]
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

    #[tool(description = "List credentials with optional filters. Never returns secret values.")]
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

    #[tool(description = "Store a new credential in the vault. Supports: password, api_token, ssh_key, database_connection, certificate, smtp_account, custom.")]
    async fn credential_store(
        &self,
        Parameters(params): Parameters<tools::storage::CredentialStoreRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::storage::credential_store(self, params).await
    }

    #[tool(description = "Delete a credential from the vault. Requires confirm=true.")]
    async fn credential_delete(
        &self,
        Parameters(params): Parameters<tools::storage::CredentialDeleteRequest>,
    ) -> Result<CallToolResult, McpError> {
        tools::storage::credential_delete(self, params).await
    }

    // ── Protocol Proxies ─────────────────────────────────────

    #[tool(description = "Make an HTTP request using a stored credential for authentication. The credential's secret is injected as auth headers and never exposed. Response is sanitized.")]
    async fn http_request(
        &self,
        Parameters(params): Parameters<tools::http::HttpRequestParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::http::http_request(self, params).await
    }

    #[tool(description = "Execute a command on a remote host via SSH using a stored credential. Output is sanitized to remove any credential values.")]
    async fn ssh_exec(
        &self,
        Parameters(params): Parameters<tools::ssh::SshExecParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ssh::ssh_exec(self, params).await
    }

    #[tool(description = "Execute a SQL query using a stored database credential. Results are sanitized. Policy can enforce read-only mode.")]
    async fn sql_query(
        &self,
        Parameters(params): Parameters<tools::sql::SqlQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::sql::sql_query(self, params).await
    }

    #[tool(description = "Send an email using a stored SMTP credential. Recipients can be restricted by policy.")]
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
                 the raw secrets. Start by calling vault_unlock with your master password.\n\n\
                 IMPORTANT — ssh_exec tips:\n\
                 - The SSH channel stays open until all output streams close. Background processes \
                   (nohup, &) will HANG the connection unless you redirect ALL file descriptors and \
                   detach from the session.\n\
                 - To run a background process: \
                   nohup <cmd> > /tmp/out.log 2>&1 < /dev/null & disown && echo \"Started PID: $!\"\n\
                 - For long-running commands, prefer: bash -c '...' to ensure clean shell handling.\n\
                 - To check if a process is running later: pgrep -f <pattern> or cat /tmp/out.log"
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
