use crate::server::PassmanServer;
use passman_types::{AuditAction, AuditEntry};
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SqlQueryParams {
    #[schemars(description = "Credential UUID (database connection)")]
    pub credential_id: String,
    #[schemars(description = "SQL query to execute")]
    pub query: String,
    #[schemars(description = "Query parameters (positional)")]
    pub params: Option<Vec<serde_json::Value>>,
}

pub async fn sql_query(
    server: &PassmanServer,
    params: SqlQueryParams,
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
        if let Err(e) = server.policy.check_tool(&policy, "sql_query") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = server.policy.check_sql_query(&policy, &params.query) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = server.policy.check_rate_limit(&policy).await {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
    }

    let input = passman_proxy::sql::SqlQueryInput {
        query: params.query.clone(),
        params: params.params,
    };

    let meta = server.vault.get_credential_meta(cred_id).await.ok();

    match passman_proxy::sql::execute(&secret, &input).await {
        Ok(output) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::SqlQuery,
                tool: "sql_query".to_string(),
                success: true,
                details: Some(params.query),
            }).await;

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({
                    "columns": output.columns,
                    "rows": output.rows,
                    "rows_affected": output.rows_affected,
                })
                .to_string(),
            )]))
        }
        Err(e) => {
            let _ = server.vault.log_audit(&AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(cred_id),
                credential_name: meta.map(|m| m.name),
                action: AuditAction::SqlQuery,
                tool: "sql_query".to_string(),
                success: false,
                details: Some(format!("{e}")),
            }).await;

            Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
        }
    }
}
