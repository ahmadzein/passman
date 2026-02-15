use chrono::Utc;
use passman_types::{
    CredentialKind, CredentialMeta, CredentialSecret, Environment, StoredCredential, VaultFile,
};
use uuid::Uuid;

use crate::crypto::DerivedKey;
use crate::VaultError;

/// Add a new credential to the vault. Returns the assigned UUID.
pub fn add_credential(
    vault: &mut VaultFile,
    key: &DerivedKey,
    name: String,
    kind: CredentialKind,
    environment: Environment,
    tags: Vec<String>,
    notes: Option<String>,
    secret: &CredentialSecret,
) -> Result<Uuid, VaultError> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    let meta = CredentialMeta {
        id,
        name,
        kind,
        environment,
        tags,
        created_at: now,
        updated_at: now,
        notes,
    };

    let secret_json = serde_json::to_vec(secret)
        .map_err(|e| VaultError::Crypto(format!("failed to serialize secret: {e}")))?;

    let encrypted = key.encrypt(&secret_json)?;

    vault.credentials.push(StoredCredential {
        meta,
        secret: encrypted,
    });

    Ok(id)
}

/// Get a credential's metadata by ID.
pub fn get_credential_meta(vault: &VaultFile, id: Uuid) -> Option<&CredentialMeta> {
    vault
        .credentials
        .iter()
        .find(|c| c.meta.id == id)
        .map(|c| &c.meta)
}

/// Decrypt and return a credential's secret by ID.
pub fn get_credential_secret(
    vault: &VaultFile,
    key: &DerivedKey,
    id: Uuid,
) -> Result<CredentialSecret, VaultError> {
    let stored = vault
        .credentials
        .iter()
        .find(|c| c.meta.id == id)
        .ok_or(VaultError::NotFound(id))?;

    let plaintext = key.decrypt(&stored.secret)?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Crypto(format!("failed to deserialize secret: {e}")))
}

/// List credential metadata, optionally filtered.
pub fn list_credentials<'a>(
    vault: &'a VaultFile,
    kind: Option<CredentialKind>,
    environment: Option<&'a Environment>,
    tag: Option<&'a str>,
) -> Vec<&'a CredentialMeta> {
    vault
        .credentials
        .iter()
        .filter(|c| {
            if let Some(k) = kind {
                if c.meta.kind != k {
                    return false;
                }
            }
            if let Some(env) = environment {
                if &c.meta.environment != env {
                    return false;
                }
            }
            if let Some(t) = tag {
                if !c.meta.tags.iter().any(|ct| ct == t) {
                    return false;
                }
            }
            true
        })
        .map(|c| &c.meta)
        .collect()
}

/// Search credentials by name (case-insensitive substring match).
pub fn search_credentials<'a>(vault: &'a VaultFile, query: &str) -> Vec<&'a CredentialMeta> {
    let query_lower = query.to_lowercase();
    vault
        .credentials
        .iter()
        .filter(|c| {
            c.meta.name.to_lowercase().contains(&query_lower)
                || c.meta
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&query_lower))
                || c.meta
                    .notes
                    .as_ref()
                    .is_some_and(|n| n.to_lowercase().contains(&query_lower))
        })
        .map(|c| &c.meta)
        .collect()
}

/// Update a credential's secret (re-encrypts with the current key).
pub fn update_credential_secret(
    vault: &mut VaultFile,
    key: &DerivedKey,
    id: Uuid,
    secret: &CredentialSecret,
) -> Result<(), VaultError> {
    let stored = vault
        .credentials
        .iter_mut()
        .find(|c| c.meta.id == id)
        .ok_or(VaultError::NotFound(id))?;

    let secret_json = serde_json::to_vec(secret)
        .map_err(|e| VaultError::Crypto(format!("failed to serialize secret: {e}")))?;

    stored.secret = key.encrypt(&secret_json)?;
    stored.meta.updated_at = Utc::now();

    Ok(())
}

/// Update a credential's metadata fields.
pub fn update_credential_meta(
    vault: &mut VaultFile,
    id: Uuid,
    name: Option<String>,
    environment: Option<Environment>,
    tags: Option<Vec<String>>,
    notes: Option<Option<String>>,
) -> Result<(), VaultError> {
    let stored = vault
        .credentials
        .iter_mut()
        .find(|c| c.meta.id == id)
        .ok_or(VaultError::NotFound(id))?;

    if let Some(n) = name {
        stored.meta.name = n;
    }
    if let Some(e) = environment {
        stored.meta.environment = e;
    }
    if let Some(t) = tags {
        stored.meta.tags = t;
    }
    if let Some(n) = notes {
        stored.meta.notes = n;
    }
    stored.meta.updated_at = Utc::now();

    Ok(())
}

/// Delete a credential by ID. Returns true if found and removed.
pub fn delete_credential(vault: &mut VaultFile, id: Uuid) -> bool {
    let len_before = vault.credentials.len();
    vault.credentials.retain(|c| c.meta.id != id);
    vault.credentials.len() < len_before
}

#[cfg(test)]
mod tests {
    use super::*;
    use passman_types::EncryptedBlob;

    fn test_vault_and_key() -> (VaultFile, DerivedKey) {
        let vault = VaultFile {
            version: 1,
            kdf_params: passman_types::KdfParams::default(),
            salt: vec![0u8; 32],
            verification: EncryptedBlob {
                nonce: vec![0u8; 12],
                ciphertext: vec![],
            },
            credentials: vec![],
            categories: vec![],
            policies: vec![],
        };
        let key = DerivedKey::new([42u8; 32]);
        (vault, key)
    }

    fn test_secret() -> CredentialSecret {
        CredentialSecret::Password {
            username: "user".to_string(),
            password: "secret123".to_string(),
            url: Some("https://example.com".to_string()),
        }
    }

    #[test]
    fn test_add_and_get() {
        let (mut vault, key) = test_vault_and_key();
        let secret = test_secret();

        let id = add_credential(
            &mut vault,
            &key,
            "Test Cred".to_string(),
            CredentialKind::Password,
            Environment::Local,
            vec!["test".to_string()],
            None,
            &secret,
        )
        .unwrap();

        let meta = get_credential_meta(&vault, id).unwrap();
        assert_eq!(meta.name, "Test Cred");
        assert_eq!(meta.kind, CredentialKind::Password);

        let decrypted = get_credential_secret(&vault, &key, id).unwrap();
        match decrypted {
            CredentialSecret::Password {
                username, password, ..
            } => {
                assert_eq!(username, "user");
                assert_eq!(password, "secret123");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_list_and_filter() {
        let (mut vault, key) = test_vault_and_key();

        add_credential(
            &mut vault,
            &key,
            "Cred A".to_string(),
            CredentialKind::Password,
            Environment::Local,
            vec!["web".to_string()],
            None,
            &test_secret(),
        )
        .unwrap();

        add_credential(
            &mut vault,
            &key,
            "Cred B".to_string(),
            CredentialKind::ApiToken,
            Environment::Production,
            vec!["api".to_string()],
            None,
            &CredentialSecret::ApiToken {
                token: "tok".to_string(),
                header_name: None,
                prefix: None,
            },
        )
        .unwrap();

        assert_eq!(list_credentials(&vault, None, None, None).len(), 2);
        assert_eq!(
            list_credentials(&vault, Some(CredentialKind::Password), None, None).len(),
            1
        );
        assert_eq!(
            list_credentials(&vault, None, Some(&Environment::Production), None).len(),
            1
        );
        assert_eq!(
            list_credentials(&vault, None, None, Some("api")).len(),
            1
        );
    }

    #[test]
    fn test_search() {
        let (mut vault, key) = test_vault_and_key();

        add_credential(
            &mut vault,
            &key,
            "GitHub API Token".to_string(),
            CredentialKind::ApiToken,
            Environment::Production,
            vec![],
            None,
            &CredentialSecret::ApiToken {
                token: "ghp_xxx".to_string(),
                header_name: None,
                prefix: None,
            },
        )
        .unwrap();

        assert_eq!(search_credentials(&vault, "github").len(), 1);
        assert_eq!(search_credentials(&vault, "GITHUB").len(), 1);
        assert_eq!(search_credentials(&vault, "nonexistent").len(), 0);
    }

    #[test]
    fn test_delete() {
        let (mut vault, key) = test_vault_and_key();

        let id = add_credential(
            &mut vault,
            &key,
            "To Delete".to_string(),
            CredentialKind::Password,
            Environment::Local,
            vec![],
            None,
            &test_secret(),
        )
        .unwrap();

        assert!(delete_credential(&mut vault, id));
        assert!(!delete_credential(&mut vault, id)); // already gone
        assert!(get_credential_meta(&vault, id).is_none());
    }
}
