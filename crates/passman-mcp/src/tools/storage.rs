use crate::server::PassmanServer;
use passman_types::{CredentialKind, CredentialSecret, Environment};
use rmcp::{model::CallToolResult, model::Content, schemars, ErrorData as McpError};
use serde::Deserialize;
use std::collections::HashMap;

// ── credential_store ─────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CredentialStoreRequest {
    #[schemars(description = "Human-readable name for the credential")]
    pub name: String,
    #[schemars(description = "Credential kind: password, api_token, ssh_key, database_connection, certificate, smtp_account, custom")]
    pub kind: String,
    #[schemars(description = "Environment: local, development, staging, production")]
    pub environment: String,
    #[schemars(description = "Secret data (structure depends on kind)")]
    pub secret: serde_json::Value,
    #[schemars(description = "Optional tags for categorization")]
    pub tags: Option<Vec<String>>,
    #[schemars(description = "Optional notes")]
    pub notes: Option<String>,
}

pub async fn credential_store(
    server: &PassmanServer,
    params: CredentialStoreRequest,
) -> Result<CallToolResult, McpError> {
    let kind: CredentialKind = serde_json::from_value(serde_json::Value::String(params.kind))
        .map_err(|_| McpError::invalid_params("invalid credential kind", None))?;

    let environment: Environment =
        serde_json::from_value(serde_json::Value::String(params.environment))
            .map_err(|_| McpError::invalid_params("invalid environment", None))?;

    let secret = parse_secret(kind, &params.secret).map_err(|e| {
        McpError::invalid_params(format!("invalid secret: {e}"), None)
    })?;

    match server
        .vault
        .store_credential(
            params.name.clone(),
            kind,
            environment,
            params.tags.unwrap_or_default(),
            params.notes,
            &secret,
        )
        .await
    {
        Ok(id) => Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "id": id.to_string(),
                "name": params.name,
            })
            .to_string(),
        )])),
        Err(e) => Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
    }
}

/// Parse the secret JSON into the correct CredentialSecret variant.
fn parse_secret(
    kind: CredentialKind,
    value: &serde_json::Value,
) -> Result<CredentialSecret, String> {
    let obj = value.as_object().ok_or("secret must be a JSON object")?;

    match kind {
        CredentialKind::Password => {
            let username = get_str(obj, "username")?;
            let password = get_str(obj, "password")?;
            let url = obj.get("url").and_then(|v| v.as_str()).map(String::from);
            Ok(CredentialSecret::Password {
                username,
                password,
                url,
            })
        }
        CredentialKind::ApiToken => {
            let token = get_str(obj, "token")?;
            let header_name = obj
                .get("header_name")
                .and_then(|v| v.as_str())
                .map(String::from);
            let prefix = obj.get("prefix").and_then(|v| v.as_str()).map(String::from);
            Ok(CredentialSecret::ApiToken {
                token,
                header_name,
                prefix,
            })
        }
        CredentialKind::SshKey => {
            let username = get_str(obj, "username")?;
            let host = get_str(obj, "host")?;
            let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
            let private_key = get_str(obj, "private_key")?;
            let passphrase = obj
                .get("passphrase")
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(CredentialSecret::SshKey {
                username,
                host,
                port,
                private_key,
                passphrase,
            })
        }
        CredentialKind::DatabaseConnection => {
            let driver_str = get_str(obj, "driver")?;
            let driver = serde_json::from_value(serde_json::Value::String(driver_str))
                .map_err(|_| "invalid driver (postgres, mysql, sqlite)")?;
            let host = get_str(obj, "host")?;
            let port = obj
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(5432) as u16;
            let database = get_str(obj, "database")?;
            let username = get_str(obj, "username")?;
            let password = get_str(obj, "password")?;
            let params: HashMap<String, String> = obj
                .get("params")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            Ok(CredentialSecret::DatabaseConnection {
                driver,
                host,
                port,
                database,
                username,
                password,
                params,
            })
        }
        CredentialKind::Certificate => {
            let cert_pem = get_str(obj, "cert_pem")?;
            let key_pem = get_str(obj, "key_pem")?;
            let ca_pem = obj
                .get("ca_pem")
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(CredentialSecret::Certificate {
                cert_pem,
                key_pem,
                ca_pem,
            })
        }
        CredentialKind::SmtpAccount => {
            let host = get_str(obj, "host")?;
            let port = obj
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(587) as u16;
            let username = get_str(obj, "username")?;
            let password = get_str(obj, "password")?;
            let encryption_str = obj
                .get("encryption")
                .and_then(|v| v.as_str())
                .unwrap_or("tls");
            let encryption =
                serde_json::from_value(serde_json::Value::String(encryption_str.to_string()))
                    .map_err(|_| "invalid encryption (none, start_tls, tls)")?;
            Ok(CredentialSecret::SmtpAccount {
                host,
                port,
                username,
                password,
                encryption,
            })
        }
        CredentialKind::Custom => {
            let mut fields = HashMap::new();
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    fields.insert(k.clone(), s.to_string());
                }
            }
            Ok(CredentialSecret::Custom { fields })
        }
    }
}

fn get_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| format!("missing required field '{key}'"))
}

// ── credential_delete ────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CredentialDeleteRequest {
    #[schemars(description = "Credential UUID to delete")]
    pub id: String,
    #[schemars(description = "Must be true to confirm deletion")]
    pub confirm: bool,
}

pub async fn credential_delete(
    server: &PassmanServer,
    params: CredentialDeleteRequest,
) -> Result<CallToolResult, McpError> {
    if !params.confirm {
        return Ok(CallToolResult::error(vec![Content::text(
            "deletion not confirmed: set confirm=true",
        )]));
    }

    let id: uuid::Uuid = params
        .id
        .parse()
        .map_err(|_| McpError::invalid_params("invalid UUID", None))?;

    match server.vault.delete_credential(id).await {
        Ok(true) => Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({ "success": true }).to_string(),
        )])),
        Ok(false) => Ok(CallToolResult::error(vec![Content::text(
            "credential not found",
        )])),
        Err(e) => Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
    }
}
