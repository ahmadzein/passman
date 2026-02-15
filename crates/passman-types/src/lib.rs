use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ── Credential Kind ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    ApiToken,
    SshKey,
    DatabaseConnection,
    Certificate,
    SmtpAccount,
    Custom,
}

impl std::fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::ApiToken => write!(f, "api_token"),
            Self::SshKey => write!(f, "ssh_key"),
            Self::DatabaseConnection => write!(f, "database_connection"),
            Self::Certificate => write!(f, "certificate"),
            Self::SmtpAccount => write!(f, "smtp_account"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

// ── Environment ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Local,
    Development,
    Staging,
    Production,
    Custom(String),
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Development => write!(f, "development"),
            Self::Staging => write!(f, "staging"),
            Self::Production => write!(f, "production"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ── Database Driver ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DbDriver {
    Postgres,
    Mysql,
    Sqlite,
}

// ── SMTP Encryption ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SmtpEncryption {
    None,
    StartTls,
    Tls,
}

// ── Credential Metadata (always plaintext, searchable) ──────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMeta {
    pub id: Uuid,
    pub name: String,
    pub kind: CredentialKind,
    pub environment: Environment,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub notes: Option<String>,
}

// ── Credential Secret (encrypted at rest) ────────────────────────
//
// Uses plain String/Vec<u8> since this struct is always serialized then
// encrypted with AES-256-GCM before any disk write. The encryption key
// is held in a zeroize-on-drop wrapper (DerivedKey) in the Vault.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialSecret {
    Password {
        username: String,
        password: String,
        url: Option<String>,
    },
    ApiToken {
        token: String,
        /// HTTP header name (e.g., "Authorization", "X-API-Key")
        header_name: Option<String>,
        /// Header value prefix (e.g., "Bearer ", "Token ")
        prefix: Option<String>,
    },
    SshKey {
        username: String,
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        private_key: String,
        passphrase: Option<String>,
    },
    DatabaseConnection {
        driver: DbDriver,
        host: String,
        port: u16,
        database: String,
        username: String,
        password: String,
        #[serde(default)]
        params: HashMap<String, String>,
    },
    Certificate {
        cert_pem: String,
        key_pem: String,
        ca_pem: Option<String>,
    },
    SmtpAccount {
        host: String,
        port: u16,
        username: String,
        password: String,
        encryption: SmtpEncryption,
    },
    Custom {
        fields: HashMap<String, String>,
    },
}

fn default_ssh_port() -> u16 {
    22
}

impl CredentialSecret {
    /// Returns all secret string values for output sanitization.
    pub fn secret_strings(&self) -> Vec<String> {
        match self {
            Self::Password { password, .. } => vec![password.clone()],
            Self::ApiToken { token, .. } => vec![token.clone()],
            Self::SshKey {
                private_key,
                passphrase,
                ..
            } => {
                let mut v = vec![private_key.clone()];
                if let Some(p) = passphrase {
                    v.push(p.clone());
                }
                v
            }
            Self::DatabaseConnection { password, .. } => vec![password.clone()],
            Self::Certificate {
                cert_pem, key_pem, ..
            } => vec![cert_pem.clone(), key_pem.clone()],
            Self::SmtpAccount { password, .. } => vec![password.clone()],
            Self::Custom { fields } => fields.values().cloned().collect(),
        }
    }
}

// ── Encrypted Blob ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ── KDF Parameters ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
        }
    }
}

// ── Stored Credential (on-disk format) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub meta: CredentialMeta,
    pub secret: EncryptedBlob,
}

// ── Category ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub name: String,
    pub description: Option<String>,
}

// ── Policy Rule ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub credential_id: Uuid,
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub http_url_patterns: Vec<String>,
    #[serde(default)]
    pub ssh_command_patterns: Vec<String>,
    #[serde(default = "default_sql_allow_write")]
    pub sql_allow_write: bool,
    #[serde(default)]
    pub smtp_allowed_recipients: Vec<String>,
    pub rate_limit: Option<RateLimit>,
}

fn default_sql_allow_write() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_requests: u32,
    pub window_secs: u64,
}

// ── Vault File (top-level on-disk structure) ─────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub kdf_params: KdfParams,
    pub salt: Vec<u8>,
    pub verification: EncryptedBlob,
    pub credentials: Vec<StoredCredential>,
    #[serde(default)]
    pub categories: Vec<Category>,
    #[serde(default)]
    pub policies: Vec<PolicyRule>,
}

// ── Audit Entry ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub credential_id: Option<Uuid>,
    pub credential_name: Option<String>,
    pub action: AuditAction,
    pub tool: String,
    pub success: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    VaultUnlock,
    VaultLock,
    CredentialList,
    CredentialSearch,
    CredentialInfo,
    CredentialStore,
    CredentialDelete,
    HttpRequest,
    SshExec,
    SqlQuery,
    SendEmail,
    AuditView,
}
