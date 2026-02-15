use crate::server::PassmanServer;
use passman_types::{AuditAction, AuditEntry};
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HttpRequestParams {
    #[schemars(description = "Credential UUID for authentication")]
    pub credential_id: String,
    #[schemars(description = "HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD")]
    pub method: String,
    #[schemars(description = "Target URL")]
    pub url: String,
    #[schemars(description = "Additional HTTP headers")]
    pub headers: Option<HashMap<String, String>>,
    #[schemars(description = "Request body")]
    pub body: Option<String>,
}

pub async fn http_request(
    server: &PassmanServer,
    params: HttpRequestParams,
) -> Result<CallToolResult, McpError> {
    let cred_id: uuid::Uuid = params
        .credential_id
        .parse()
        .map_err(|_| McpError::invalid_params("invalid UUID", None))?;

    // Get the credential secret (never exposed to LLM)
    let secret = server
        .vault
        .get_credential_secret(cred_id)
        .await
        .map_err(|e| McpError::internal_error(format!("{e}"), None))?;

    // Check policy
    if let Ok(Some(policy)) = server.vault.get_policy(cred_id).await {
        if let Err(e) = server.policy.check_tool(&policy, "http_request") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = server.policy.check_http_url(&policy, &params.url) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = server.policy.check_rate_limit(&policy).await {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
    }

    let input = passman_proxy::http::HttpRequestInput {
        method: params.method,
        url: params.url.clone(),
        headers: params.headers,
        body: params.body,
    };

    let meta = server.vault.get_credential_meta(cred_id).await.ok();

    match passman_proxy::http::execute(&secret, &input).await {
        Ok(response) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::HttpRequest,
                tool: "http_request".to_string(),
                success: true,
                details: Some(format!("{} {}", input.method, params.url)),
            }).await;

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({
                    "status": response.status,
                    "headers": response.headers,
                    "body": response.body,
                })
                .to_string(),
            )]))
        }
        Err(e) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::HttpRequest,
                tool: "http_request".to_string(),
                success: false,
                details: Some(format!("{e}")),
            }).await;

            Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
        }
    }
}
