use crate::server::PassmanServer;
use passman_types::{AuditAction, AuditEntry};
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendEmailParams {
    #[schemars(description = "Credential UUID (SMTP account)")]
    pub credential_id: String,
    #[schemars(description = "Recipient email addresses")]
    pub to: Vec<String>,
    #[schemars(description = "Email subject")]
    pub subject: String,
    #[schemars(description = "Email body (plain text)")]
    pub body: String,
    #[schemars(description = "CC recipients")]
    pub cc: Option<Vec<String>>,
    #[schemars(description = "BCC recipients")]
    pub bcc: Option<Vec<String>>,
}

pub async fn send_email(
    server: &PassmanServer,
    params: SendEmailParams,
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
        if let Err(e) = server.policy.check_tool(&policy, "send_email") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        // Check each recipient
        for recipient in params.to.iter().chain(params.cc.iter().flatten()).chain(params.bcc.iter().flatten()) {
            if let Err(e) = server.policy.check_smtp_recipient(&policy, recipient) {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
            }
        }
        if let Err(e) = server.policy.check_rate_limit(&policy).await {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
    }

    let input = passman_proxy::smtp::SendEmailInput {
        to: params.to.clone(),
        subject: params.subject,
        body: params.body,
        cc: params.cc,
        bcc: params.bcc,
        from: None,
    };

    let meta = server.vault.get_credential_meta(cred_id).await.ok();

    match passman_proxy::smtp::execute(&secret, &input).await {
        Ok(output) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::SendEmail,
                tool: "send_email".to_string(),
                success: output.success,
                details: Some(format!("to: {}", params.to.join(", "))),
            }).await;

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({
                    "success": output.success,
                    "message_id": output.message_id,
                })
                .to_string(),
            )]))
        }
        Err(e) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::SendEmail,
                tool: "send_email".to_string(),
                success: false,
                details: Some(format!("{e}")),
            }).await;

            Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
        }
    }
}
