use passman_types::{CredentialSecret, DbDriver};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Column, Row};
use sqlx::any::AnyRow;

use crate::sanitizer;
use crate::ProxyError;

#[derive(Debug, Deserialize)]
pub struct SqlQueryInput {
    pub query: String,
    pub params: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct SqlQueryOutput {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub rows_affected: u64,
}

/// Build a connection URL from the database credential.
fn build_connection_url(secret: &CredentialSecret) -> Result<String, ProxyError> {
    match secret {
        CredentialSecret::DatabaseConnection {
            driver,
            host,
            port,
            database,
            username,
            password,
            params,
        } => {
            let scheme = match driver {
                DbDriver::Postgres => "postgres",
                DbDriver::Mysql => "mysql",
                DbDriver::Sqlite => "sqlite",
            };

            if matches!(driver, DbDriver::Sqlite) {
                return Ok(format!("sqlite:{database}"));
            }

            let encoded_password = urlencoding::encode(password);

            let mut url =
                format!("{scheme}://{username}:{encoded_password}@{host}:{port}/{database}");

            if !params.is_empty() {
                let query: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
                url.push('?');
                url.push_str(&query.join("&"));
            }

            Ok(url)
        }
        _ => Err(ProxyError::InvalidInput(
            "credential type not supported for SQL".to_string(),
        )),
    }
}

/// Extract a column value from a row as a JSON value.
fn extract_value(row: &AnyRow, idx: usize) -> serde_json::Value {
    if let Ok(v) = row.try_get::<i64, _>(idx) {
        return serde_json::Value::Number(v.into());
    }
    if let Ok(v) = row.try_get::<f64, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<bool, _>(idx) {
        return serde_json::Value::Bool(v);
    }
    if let Ok(v) = row.try_get::<String, _>(idx) {
        return serde_json::Value::String(v);
    }
    if let Ok(v) = row.try_get::<i32, _>(idx) {
        return serde_json::Value::Number(v.into());
    }
    serde_json::Value::Null
}

/// Execute a SQL query using the stored credential.
pub async fn execute(
    secret: &CredentialSecret,
    input: &SqlQueryInput,
) -> Result<SqlQueryOutput, ProxyError> {
    let url = build_connection_url(secret)?;

    let pool: AnyPool = AnyPool::connect(&url)
        .await
        .map_err(|e| ProxyError::Protocol(format!("SQL connection failed: {e}")))?;

    let rows: Vec<AnyRow> = sqlx::query(&input.query)
        .fetch_all(&pool)
        .await
        .map_err(|e| ProxyError::Protocol(format!("SQL query failed: {e}")))?;

    let columns: Vec<String> = if let Some(first) = rows.first() {
        first
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect()
    } else {
        vec![]
    };

    let result_rows: Vec<Vec<serde_json::Value>> = rows
        .iter()
        .map(|row: &AnyRow| {
            (0..columns.len())
                .map(|i| extract_value(row, i))
                .collect()
        })
        .collect();

    pool.close().await;

    // Sanitize all string values in the results
    let secrets = secret.secret_strings();
    let sanitized_rows: Vec<Vec<serde_json::Value>> = result_rows
        .into_iter()
        .map(|row: Vec<serde_json::Value>| {
            row.into_iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => {
                        serde_json::Value::String(sanitizer::sanitize(&s, &secrets))
                    }
                    other => other,
                })
                .collect()
        })
        .collect();

    Ok(SqlQueryOutput {
        columns,
        rows: sanitized_rows,
        rows_affected: 0,
    })
}
