use crate::server::PassmanServer;
use passman_types::{AuditAction, AuditEntry};
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshExecParams {
    #[schemars(description = "Credential UUID (SSH key or password)")]
    pub credential_id: String,
    #[schemars(description = "Shell command to execute on the remote host")]
    pub command: String,
}

pub async fn ssh_exec(
    server: &PassmanServer,
    params: SshExecParams,
) -> Result<CallToolResult, McpError> {
    let cred_id: uuid::Uuid = params
        .credential_id
        .parse()
        .map_err(|_| McpError::invalid_params("invalid UUID", None))?;

    let secret = server
        .vault
        .get_credential_secret(cred_id)
        .await
        .map_err(|e| McpError::internal_error(format!("{e}"), None))?;

    // Check policy
    if let Ok(Some(policy)) = server.vault.get_policy(cred_id).await {
        if let Err(e) = server.policy.check_tool(&policy, "ssh_exec") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = server.policy.check_ssh_command(&policy, &params.command) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = server.policy.check_rate_limit(&policy).await {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
    }

    let input = passman_proxy::ssh::SshExecInput {
        command: params.command.clone(),
    };

    let meta = server.vault.get_credential_meta(cred_id).await.ok();

    match passman_proxy::ssh::execute(&secret, &input).await {
        Ok(output) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::SshExec,
                tool: "ssh_exec".to_string(),
                success: output.exit_code == 0,
                details: Some(params.command),
            }).await;

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({
                    "exit_code": output.exit_code,
                    "stdout": output.stdout,
                    "stderr": output.stderr,
                })
                .to_string(),
            )]))
        }
        Err(e) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::SshExec,
                tool: "ssh_exec".to_string(),
                success: false,
                details: Some(format!("{e}")),
            }).await;

            Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
        }
    }
}
