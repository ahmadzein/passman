use crate::server::PassmanServer;
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;

// ── vault_unlock ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VaultUnlockRequest {
    #[schemars(description = "Master password to unlock the vault")]
    pub password: String,
}

pub async fn vault_unlock(
    server: &PassmanServer,
    params: VaultUnlockRequest,
) -> Result<CallToolResult, McpError> {
    // Check if vault exists; if not, create it
    if !server.vault.exists().await {
        match server.vault.create(&params.password).await {
            Ok(()) => {
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::json!({
                        "success": true,
                        "credential_count": 0,
                        "message": "New vault created and unlocked"
                    })
                    .to_string(),
                )]));
            }
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to create vault: {e}"
                ))]));
            }
        }
    }

    match server.vault.unlock(&params.password).await {
        Ok(count) => Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "success": true,
                "credential_count": count
            })
            .to_string(),
        )])),
        Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
            "Failed to unlock vault: {e}"
        ))])),
    }
}

// ── vault_lock ───────────────────────────────────────────────────

pub async fn vault_lock(server: &PassmanServer) -> Result<CallToolResult, McpError> {
    server.vault.lock().await;
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({ "success": true }).to_string(),
    )]))
}

// ── vault_status ─────────────────────────────────────────────────

pub async fn vault_status(server: &PassmanServer) -> Result<CallToolResult, McpError> {
    let locked = !server.vault.is_unlocked().await;
    let exists = server.vault.exists().await;

    if locked {
        return Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "exists": exists,
                "locked": true,
            })
            .to_string(),
        )]));
    }

    let count = server.vault.credential_count().await.unwrap_or(0);
    let envs = server.vault.get_environments().await.unwrap_or_default();

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "exists": exists,
            "locked": false,
            "credential_count": count,
            "environments": envs,
        })
        .to_string(),
    )]))
}
