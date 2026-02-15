use crate::server::PassmanServer;
use passman_types::{AuditAction, AuditEntry, CredentialKind, Environment};
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;

// ── credential_list ──────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CredentialListRequest {
    #[schemars(description = "Filter by credential kind: password, api_token, ssh_key, database_connection, certificate, smtp_account, custom")]
    pub kind: Option<String>,
    #[schemars(description = "Filter by environment: local, development, staging, production")]
    pub environment: Option<String>,
    #[schemars(description = "Filter by tag")]
    pub tag: Option<String>,
}

pub async fn credential_list(
    server: &PassmanServer,
    params: CredentialListRequest,
) -> Result<CallToolResult, McpError> {
    let kind: Option<CredentialKind> = params
        .kind
        .as_deref()
        .map(|k| serde_json::from_value(serde_json::Value::String(k.to_string())))
        .transpose()
        .map_err(|_| McpError::invalid_params("invalid credential kind", None))?;

    let environment: Option<Environment> = params
        .environment
        .as_deref()
        .map(|e| serde_json::from_value(serde_json::Value::String(e.to_string())))
        .transpose()
        .map_err(|_| McpError::invalid_params("invalid environment", None))?;

    match server
        .vault
        .list_credentials(kind, environment, params.tag)
        .await
    {
        Ok(creds) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: None,
                credential_name: None,
                action: AuditAction::CredentialList,
                tool: "credential_list".to_string(),
                success: true,
                details: None,
            }).await;

            let items: Vec<serde_json::Value> = creds
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id.to_string(),
                        "name": c.name,
                        "kind": c.kind,
                        "environment": c.environment,
                        "tags": c.tags,
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

// ── credential_search ────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CredentialSearchRequest {
    #[schemars(description = "Search query (matches name, tags, notes)")]
    pub query: String,
}

pub async fn credential_search(
    server: &PassmanServer,
    params: CredentialSearchRequest,
) -> Result<CallToolResult, McpError> {
    match server.vault.search_credentials(&params.query).await {
        Ok(creds) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: None,
                credential_name: None,
                action: AuditAction::CredentialSearch,
                tool: "credential_search".to_string(),
                success: true,
                details: Some(format!("query: {}", params.query)),
            }).await;

            let items: Vec<serde_json::Value> = creds
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id.to_string(),
                        "name": c.name,
                        "kind": c.kind,
                        "environment": c.environment,
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

// ── credential_info ──────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CredentialInfoRequest {
    #[schemars(description = "Credential UUID")]
    pub id: String,
}

pub async fn credential_info(
    server: &PassmanServer,
    params: CredentialInfoRequest,
) -> Result<CallToolResult, McpError> {
    let id: uuid::Uuid = params
        .id
        .parse()
        .map_err(|_| McpError::invalid_params("invalid UUID", None))?;

    match server.vault.get_credential_meta(id).await {
        Ok(meta) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(id),
                credential_name: Some(meta.name.clone()),
                action: AuditAction::CredentialInfo,
                tool: "credential_info".to_string(),
                success: true,
                details: None,
            }).await;

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({
                    "id": meta.id.to_string(),
                    "name": meta.name,
                    "kind": meta.kind,
                    "environment": meta.environment,
                    "tags": meta.tags,
                    "notes": meta.notes,
                    "created_at": meta.created_at.to_rfc3339(),
                    "updated_at": meta.updated_at.to_rfc3339(),
                })
                .to_string(),
            )]))
        }
        Err(e) => Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
    }
}
