pub mod audit;
pub mod credential;
pub mod crypto;
pub mod storage;
pub mod watcher;

use passman_types::{
    AuditAction, AuditEntry, CredentialKind, CredentialMeta, CredentialSecret, Environment,
    PolicyRule, VaultFile,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Errors ───────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,

    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),

    #[error("invalid master password")]
    InvalidPassword,

    #[error("credential not found: {0}")]
    NotFound(Uuid),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(String),
}

// ── Vault (thread-safe handle) ───────────────────────────────────

/// Thread-safe vault handle for use across MCP tools and the GUI.
#[derive(Clone)]
pub struct Vault {
    inner: Arc<RwLock<VaultInner>>,
}

struct VaultInner {
    vault_path: PathBuf,
    audit_path: PathBuf,
    state: VaultState,
}

enum VaultState {
    Locked,
    Unlocked {
        key: crypto::DerivedKey,
        data: VaultFile,
    },
}

impl Vault {
    /// Create a new Vault handle pointing at the given paths.
    pub fn new(vault_path: PathBuf, audit_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(RwLock::new(VaultInner {
                vault_path,
                audit_path,
                state: VaultState::Locked,
            })),
        }
    }

    /// Create a Vault with default paths (~/.passman/).
    pub fn with_defaults() -> Self {
        Self::new(storage::default_vault_path(), storage::default_audit_path())
    }

    /// Get the vault file path.
    pub async fn vault_path(&self) -> PathBuf {
        self.inner.read().await.vault_path.clone()
    }

    /// Create a new vault file with the given master password.
    pub async fn create(&self, password: &str) -> Result<(), VaultError> {
        let inner = self.inner.read().await;
        if storage::vault_exists(&inner.vault_path) {
            return Err(VaultError::AlreadyExists(inner.vault_path.clone()));
        }
        drop(inner);

        let salt = crypto::generate_salt();
        let params = passman_types::KdfParams::default();
        let key_bytes = crypto::derive_key(password, &salt, &params)?;
        let verification = crypto::create_verification(&key_bytes)?;

        let vault_file = VaultFile {
            version: 1,
            kdf_params: params,
            salt: salt.to_vec(),
            verification,
            credentials: vec![],
            categories: vec![],
            policies: vec![],
        };

        let mut inner = self.inner.write().await;
        storage::save_vault(&inner.vault_path, &vault_file)?;
        inner.state = VaultState::Unlocked {
            key: crypto::DerivedKey::new(key_bytes),
            data: vault_file,
        };

        Ok(())
    }

    /// Unlock the vault with the master password.
    pub async fn unlock(&self, password: &str) -> Result<usize, VaultError> {
        let inner = self.inner.read().await;
        let vault_file = storage::load_vault(&inner.vault_path)?;
        drop(inner);

        let key_bytes = crypto::derive_key(password, &vault_file.salt, &vault_file.kdf_params)?;

        if !crypto::verify_password(&key_bytes, &vault_file.verification)? {
            return Err(VaultError::InvalidPassword);
        }

        let count = vault_file.credentials.len();
        let mut inner = self.inner.write().await;
        inner.state = VaultState::Unlocked {
            key: crypto::DerivedKey::new(key_bytes),
            data: vault_file,
        };

        Ok(count)
    }

    /// Lock the vault, zeroing the key from memory.
    pub async fn lock(&self) {
        let mut inner = self.inner.write().await;
        inner.state = VaultState::Locked;
    }

    /// Check if the vault is currently unlocked.
    pub async fn is_unlocked(&self) -> bool {
        let inner = self.inner.read().await;
        matches!(inner.state, VaultState::Unlocked { .. })
    }

    /// Check if a vault file exists on disk.
    pub async fn exists(&self) -> bool {
        let inner = self.inner.read().await;
        storage::vault_exists(&inner.vault_path)
    }

    /// Get credential count.
    pub async fn credential_count(&self) -> Result<usize, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => Ok(data.credentials.len()),
        }
    }

    /// Store a new credential. Returns the new credential ID.
    pub async fn store_credential(
        &self,
        name: String,
        kind: CredentialKind,
        environment: Environment,
        tags: Vec<String>,
        notes: Option<String>,
        secret: &CredentialSecret,
    ) -> Result<Uuid, VaultError> {
        let mut inner = self.inner.write().await;
        let vault_path = inner.vault_path.clone();
        let audit_path = inner.audit_path.clone();

        let (key, data) = match &mut inner.state {
            VaultState::Locked => return Err(VaultError::Locked),
            VaultState::Unlocked { key, data } => (key, data),
        };

        let id = credential::add_credential(data, key, name, kind, environment, tags, notes, secret)?;
        let cred_name = data
            .credentials
            .iter()
            .find(|c| c.meta.id == id)
            .map(|c| c.meta.name.clone());
        storage::save_vault(&vault_path, data)?;

        let _ = audit::append_entry(
            &audit_path,
            &AuditEntry {
                timestamp: chrono::Utc::now(),
                credential_id: Some(id),
                credential_name: cred_name,
                action: AuditAction::CredentialStore,
                tool: "credential_store".to_string(),
                success: true,
                details: None,
            },
        );

        Ok(id)
    }

    /// Get credential metadata by ID.
    pub async fn get_credential_meta(&self, id: Uuid) -> Result<CredentialMeta, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => {
                credential::get_credential_meta(data, id)
                    .cloned()
                    .ok_or(VaultError::NotFound(id))
            }
        }
    }

    /// Get a credential's decrypted secret.
    pub async fn get_credential_secret(
        &self,
        id: Uuid,
    ) -> Result<CredentialSecret, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { key, data } => {
                credential::get_credential_secret(data, key, id)
            }
        }
    }

    /// List credentials with optional filters.
    pub async fn list_credentials(
        &self,
        kind: Option<CredentialKind>,
        environment: Option<Environment>,
        tag: Option<String>,
    ) -> Result<Vec<CredentialMeta>, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => {
                Ok(credential::list_credentials(
                    data,
                    kind,
                    environment.as_ref(),
                    tag.as_deref(),
                )
                .into_iter()
                .cloned()
                .collect())
            }
        }
    }

    /// Search credentials by query string.
    pub async fn search_credentials(&self, query: &str) -> Result<Vec<CredentialMeta>, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => Ok(credential::search_credentials(data, query)
                .into_iter()
                .cloned()
                .collect()),
        }
    }

    /// Delete a credential by ID.
    pub async fn delete_credential(&self, id: Uuid) -> Result<bool, VaultError> {
        let mut inner = self.inner.write().await;
        let vault_path = inner.vault_path.clone();
        let audit_path = inner.audit_path.clone();

        let data = match &mut inner.state {
            VaultState::Locked => return Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => data,
        };

        let deleted = credential::delete_credential(data, id);
        if deleted {
            storage::save_vault(&vault_path, data)?;

            let _ = audit::append_entry(
                &audit_path,
                &AuditEntry {
                    timestamp: chrono::Utc::now(),
                    credential_id: Some(id),
                    credential_name: None,
                    action: AuditAction::CredentialDelete,
                    tool: "credential_delete".to_string(),
                    success: true,
                    details: None,
                },
            );
        }

        Ok(deleted)
    }

    /// Get the policy for a credential, if any.
    pub async fn get_policy(&self, credential_id: Uuid) -> Result<Option<PolicyRule>, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => Ok(data
                .policies
                .iter()
                .find(|p| p.credential_id == credential_id)
                .cloned()),
        }
    }

    /// Save (create or update) a policy for a credential.
    pub async fn save_policy(&self, policy: PolicyRule) -> Result<(), VaultError> {
        let mut inner = self.inner.write().await;
        let vault_path = inner.vault_path.clone();

        let data = match &mut inner.state {
            VaultState::Locked => return Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => data,
        };

        // Verify the credential exists
        if !data.credentials.iter().any(|c| c.meta.id == policy.credential_id) {
            return Err(VaultError::NotFound(policy.credential_id));
        }

        // Upsert: remove old policy for this credential, then add new one
        data.policies.retain(|p| p.credential_id != policy.credential_id);
        data.policies.push(policy);
        storage::save_vault(&vault_path, data)?;
        Ok(())
    }

    /// Delete the policy for a credential.
    pub async fn delete_policy(&self, credential_id: Uuid) -> Result<bool, VaultError> {
        let mut inner = self.inner.write().await;
        let vault_path = inner.vault_path.clone();

        let data = match &mut inner.state {
            VaultState::Locked => return Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => data,
        };

        let before = data.policies.len();
        data.policies.retain(|p| p.credential_id != credential_id);
        let removed = data.policies.len() < before;
        if removed {
            storage::save_vault(&vault_path, data)?;
        }
        Ok(removed)
    }

    /// Get all policies.
    pub async fn get_all_policies(&self) -> Result<Vec<PolicyRule>, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => Ok(data.policies.clone()),
        }
    }

    /// Get all categories/environments in use.
    pub async fn get_environments(&self) -> Result<Vec<String>, VaultError> {
        let inner = self.inner.read().await;
        match &inner.state {
            VaultState::Locked => Err(VaultError::Locked),
            VaultState::Unlocked { data, .. } => {
                let mut envs: Vec<String> = data
                    .credentials
                    .iter()
                    .map(|c| c.meta.environment.to_string())
                    .collect();
                envs.sort();
                envs.dedup();
                Ok(envs)
            }
        }
    }

    /// Append an audit entry.
    pub async fn log_audit(&self, entry: &AuditEntry) -> Result<(), VaultError> {
        let inner = self.inner.read().await;
        audit::append_entry(&inner.audit_path, entry)
    }

    /// Read audit entries with optional filters.
    pub async fn read_audit(
        &self,
        credential_id: Option<Uuid>,
        limit: Option<usize>,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditEntry>, VaultError> {
        let inner = self.inner.read().await;
        audit::read_entries(&inner.audit_path, credential_id, limit, since)
    }

    /// Reload vault data from disk (used when another process writes the file).
    pub async fn reload(&self) -> Result<(), VaultError> {
        let mut inner = self.inner.write().await;
        match &inner.state {
            VaultState::Locked => Ok(()),
            VaultState::Unlocked { key, .. } => {
                let vault_file = storage::load_vault(&inner.vault_path)?;
                // Verify the key still works
                if !crypto::verify_password(key.as_bytes(), &vault_file.verification)? {
                    inner.state = VaultState::Locked;
                    return Err(VaultError::InvalidPassword);
                }
                // Re-derive the key reference — the key stays the same
                let key_bytes = *key.as_bytes();
                inner.state = VaultState::Unlocked {
                    key: crypto::DerivedKey::new(key_bytes),
                    data: vault_file,
                };
                Ok(())
            }
        }
    }
}
