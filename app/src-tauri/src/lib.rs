use passman_types::{
    AuditEntry, CredentialKind, CredentialMeta, CredentialSecret, Environment, PolicyRule,
};
use passman_vault::Vault;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Serializable error for Tauri commands ───────────────────────

#[derive(Debug, Serialize)]
pub struct CommandError {
    pub message: String,
}

impl From<passman_vault::VaultError> for CommandError {
    fn from(e: passman_vault::VaultError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

type CmdResult<T> = Result<T, CommandError>;

// ── Vault management ────────────────────────────────────────────

#[tauri::command]
async fn vault_exists(vault: tauri::State<'_, Vault>) -> CmdResult<bool> {
    Ok(vault.exists().await)
}

#[tauri::command]
async fn vault_create(vault: tauri::State<'_, Vault>, password: String) -> CmdResult<()> {
    vault.create(&password).await?;
    Ok(())
}

#[tauri::command]
async fn vault_unlock(vault: tauri::State<'_, Vault>, password: String) -> CmdResult<usize> {
    Ok(vault.unlock(&password).await?)
}

#[tauri::command]
async fn vault_lock(vault: tauri::State<'_, Vault>) -> CmdResult<()> {
    vault.lock().await;
    Ok(())
}

#[tauri::command]
async fn vault_status(vault: tauri::State<'_, Vault>) -> CmdResult<VaultStatusResponse> {
    let unlocked = vault.is_unlocked().await;
    let credential_count = if unlocked {
        vault.credential_count().await.unwrap_or(0)
    } else {
        0
    };
    let environments = if unlocked {
        vault.get_environments().await.unwrap_or_default()
    } else {
        vec![]
    };

    Ok(VaultStatusResponse {
        unlocked,
        credential_count,
        environments,
    })
}

#[derive(Serialize)]
struct VaultStatusResponse {
    unlocked: bool,
    credential_count: usize,
    environments: Vec<String>,
}

// ── Credential CRUD ─────────────────────────────────────────────

#[tauri::command]
async fn credential_list(
    vault: tauri::State<'_, Vault>,
    kind: Option<String>,
    environment: Option<String>,
    tag: Option<String>,
) -> CmdResult<Vec<CredentialMeta>> {
    let kind = kind.and_then(|k| serde_json::from_value(serde_json::Value::String(k)).ok());
    let env = environment.and_then(|e| parse_environment(&e));
    Ok(vault.list_credentials(kind, env, tag).await?)
}

#[tauri::command]
async fn credential_search(
    vault: tauri::State<'_, Vault>,
    query: String,
) -> CmdResult<Vec<CredentialMeta>> {
    Ok(vault.search_credentials(&query).await?)
}

#[tauri::command]
async fn credential_info(
    vault: tauri::State<'_, Vault>,
    id: String,
) -> CmdResult<CredentialMeta> {
    let uuid = parse_uuid(&id)?;
    Ok(vault.get_credential_meta(uuid).await?)
}

#[tauri::command]
async fn credential_get_secret(
    vault: tauri::State<'_, Vault>,
    id: String,
) -> CmdResult<CredentialSecret> {
    let uuid = parse_uuid(&id)?;
    Ok(vault.get_credential_secret(uuid).await?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreCredentialInput {
    pub name: String,
    pub kind: String,
    pub environment: String,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub secret: serde_json::Value,
}

#[tauri::command]
async fn credential_store(
    vault: tauri::State<'_, Vault>,
    input: StoreCredentialInput,
) -> CmdResult<String> {
    let kind: CredentialKind = serde_json::from_value(serde_json::Value::String(input.kind))
        .map_err(|e| CommandError {
            message: format!("invalid kind: {e}"),
        })?;
    let env = parse_environment(&input.environment).ok_or_else(|| CommandError {
        message: format!("invalid environment: {}", input.environment),
    })?;
    let secret: CredentialSecret =
        serde_json::from_value(input.secret).map_err(|e| CommandError {
            message: format!("invalid secret: {e}"),
        })?;

    let id = vault
        .store_credential(input.name, kind, env, input.tags, input.notes, &secret)
        .await?;
    Ok(id.to_string())
}

#[tauri::command]
async fn credential_delete(vault: tauri::State<'_, Vault>, id: String) -> CmdResult<bool> {
    let uuid = parse_uuid(&id)?;
    Ok(vault.delete_credential(uuid).await?)
}

// ── Audit ───────────────────────────────────────────────────────

#[tauri::command]
async fn audit_log(
    vault: tauri::State<'_, Vault>,
    credential_id: Option<String>,
    limit: Option<usize>,
) -> CmdResult<Vec<AuditEntry>> {
    let cred_id = credential_id
        .map(|id| parse_uuid(&id))
        .transpose()?;
    Ok(vault.read_audit(cred_id, limit, None).await?)
}

// ── Policy ──────────────────────────────────────────────────────

#[tauri::command]
async fn policy_get(
    vault: tauri::State<'_, Vault>,
    credential_id: String,
) -> CmdResult<Option<PolicyRule>> {
    let uuid = parse_uuid(&credential_id)?;
    Ok(vault.get_policy(uuid).await?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavePolicyInput {
    pub credential_id: String,
    pub allowed_tools: Vec<String>,
    pub http_url_patterns: Vec<String>,
    pub ssh_command_patterns: Vec<String>,
    pub sql_allow_write: bool,
    pub smtp_allowed_recipients: Vec<String>,
    pub rate_limit: Option<RateLimitInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitInput {
    pub max_requests: u32,
    pub window_secs: u64,
}

#[tauri::command]
async fn policy_save(
    vault: tauri::State<'_, Vault>,
    input: SavePolicyInput,
) -> CmdResult<()> {
    let uuid = parse_uuid(&input.credential_id)?;
    let policy = PolicyRule {
        credential_id: uuid,
        allowed_tools: input.allowed_tools,
        http_url_patterns: input.http_url_patterns,
        ssh_command_patterns: input.ssh_command_patterns,
        sql_allow_write: input.sql_allow_write,
        smtp_allowed_recipients: input.smtp_allowed_recipients,
        rate_limit: input.rate_limit.map(|r| passman_types::RateLimit {
            max_requests: r.max_requests,
            window_secs: r.window_secs,
        }),
    };
    vault.save_policy(policy).await?;
    Ok(())
}

#[tauri::command]
async fn policy_delete(
    vault: tauri::State<'_, Vault>,
    credential_id: String,
) -> CmdResult<bool> {
    let uuid = parse_uuid(&credential_id)?;
    Ok(vault.delete_policy(uuid).await?)
}

// ── MCP Server management ──────────────────────────────────────

#[derive(Serialize)]
struct McpStatus {
    installed: bool,
    path: Option<String>,
}

#[tauri::command]
async fn check_mcp_installed() -> CmdResult<McpStatus> {
    // Check PATH first
    if let Ok(path) = which::which("passman-mcp-server") {
        return Ok(McpStatus {
            installed: true,
            path: Some(path.to_string_lossy().to_string()),
        });
    }

    // Fall back to common install locations
    let home = dirs_next().unwrap_or_default();
    let candidates = [
        format!("{}/.local/bin/passman-mcp-server", home),
        format!("{}/bin/passman-mcp-server", home),
    ];

    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() {
            return Ok(McpStatus {
                installed: true,
                path: Some(candidate.clone()),
            });
        }
    }

    Ok(McpStatus {
        installed: false,
        path: None,
    })
}

#[tauri::command]
async fn install_mcp_server() -> CmdResult<String> {
    let target = detect_target()?;
    let url = format!(
        "https://github.com/ahmadzein/passman/releases/latest/download/passman-mcp-server-{}.tar.gz",
        target
    );

    let home = dirs_next().unwrap_or_default();
    let install_dir = format!("{}/.local/bin", home);
    std::fs::create_dir_all(&install_dir).map_err(|e| CommandError {
        message: format!("Failed to create install directory: {e}"),
    })?;

    let install_path = format!("{}/passman-mcp-server", install_dir);

    // Download tarball
    let response = reqwest::blocking::get(&url).map_err(|e| CommandError {
        message: format!("Download failed: {e}"),
    })?;

    if !response.status().is_success() {
        return Err(CommandError {
            message: format!("Download failed: HTTP {}", response.status()),
        });
    }

    let bytes = response.bytes().map_err(|e| CommandError {
        message: format!("Failed to read response: {e}"),
    })?;

    // Extract tar.gz
    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().map_err(|e| CommandError {
        message: format!("Failed to read archive: {e}"),
    })? {
        let mut entry = entry.map_err(|e| CommandError {
            message: format!("Failed to read archive entry: {e}"),
        })?;

        let path = entry.path().map_err(|e| CommandError {
            message: format!("Failed to read entry path: {e}"),
        })?;

        if path.file_name().and_then(|n| n.to_str()) == Some("passman-mcp-server") {
            let mut file = std::fs::File::create(&install_path).map_err(|e| CommandError {
                message: format!("Failed to create binary: {e}"),
            })?;
            std::io::copy(&mut entry, &mut file).map_err(|e| CommandError {
                message: format!("Failed to write binary: {e}"),
            })?;
            break;
        }
    }

    // chmod +x
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&install_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| CommandError {
                message: format!("Failed to set permissions: {e}"),
            })?;
    }

    Ok(install_path)
}

fn dirs_next() -> Option<String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
}

fn detect_target() -> Result<String, CommandError> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    match (os, arch) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin".to_string()),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin".to_string()),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu".to_string()),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu".to_string()),
        _ => Err(CommandError {
            message: format!("Unsupported platform: {os}/{arch}"),
        }),
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn parse_uuid(s: &str) -> Result<Uuid, CommandError> {
    Uuid::parse_str(s).map_err(|e| CommandError {
        message: format!("invalid UUID: {e}"),
    })
}

fn parse_environment(s: &str) -> Option<Environment> {
    match s.to_lowercase().as_str() {
        "local" => Some(Environment::Local),
        "development" => Some(Environment::Development),
        "staging" => Some(Environment::Staging),
        "production" => Some(Environment::Production),
        other => Some(Environment::Custom(other.to_string())),
    }
}

// ── App entry ───────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vault = Vault::with_defaults();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(vault)
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            vault_create,
            vault_unlock,
            vault_lock,
            vault_status,
            credential_list,
            credential_search,
            credential_info,
            credential_get_secret,
            credential_store,
            credential_delete,
            audit_log,
            policy_get,
            policy_save,
            policy_delete,
            check_mcp_installed,
            install_mcp_server,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Passman");
}
