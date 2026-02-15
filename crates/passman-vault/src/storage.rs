use fd_lock::RwLock;
use passman_types::VaultFile;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::VaultError;

/// Default vault directory: ~/.passman/
pub fn default_vault_dir() -> PathBuf {
    dirs_home().join(".passman")
}

/// Default vault file path: ~/.passman/vault.json
pub fn default_vault_path() -> PathBuf {
    default_vault_dir().join("vault.json")
}

/// Default audit log path: ~/.passman/audit.jsonl
pub fn default_audit_path() -> PathBuf {
    default_vault_dir().join("audit.jsonl")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Ensure the vault directory exists.
pub fn ensure_vault_dir(path: &Path) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VaultError::Io(format!("failed to create vault directory: {e}")))?;
    }
    Ok(())
}

/// Load the vault file from disk with a read lock.
pub fn load_vault(path: &Path) -> Result<VaultFile, VaultError> {
    let file = fs::File::open(path)
        .map_err(|e| VaultError::Io(format!("failed to open vault file: {e}")))?;

    let lock = RwLock::new(file);
    // Acquire read lock (blocks until available), then drop it
    let _guard = lock
        .read()
        .map_err(|e| VaultError::Io(format!("failed to acquire read lock: {e}")))?;
    drop(_guard);

    // Read file contents after confirming lock was obtainable
    let contents = fs::read_to_string(path)
        .map_err(|e| VaultError::Io(format!("failed to read vault file: {e}")))?;

    serde_json::from_str(&contents)
        .map_err(|e| VaultError::Io(format!("failed to parse vault file: {e}")))
}

/// Save the vault file to disk with a write lock.
pub fn save_vault(path: &Path, vault: &VaultFile) -> Result<(), VaultError> {
    ensure_vault_dir(path)?;

    let temp_path = path.with_extension("json.tmp");

    // Write to temp file first
    let contents = serde_json::to_string_pretty(vault)
        .map_err(|e| VaultError::Io(format!("failed to serialize vault: {e}")))?;

    {
        let file = fs::File::create(&temp_path)
            .map_err(|e| VaultError::Io(format!("failed to create temp file: {e}")))?;

        let mut lock = RwLock::new(file);
        let mut guard = lock
            .write()
            .map_err(|e| VaultError::Io(format!("failed to acquire write lock: {e}")))?;

        guard
            .write_all(contents.as_bytes())
            .map_err(|e| VaultError::Io(format!("failed to write temp file: {e}")))?;

        guard
            .flush()
            .map_err(|e| VaultError::Io(format!("failed to flush temp file: {e}")))?;
    }

    // Atomic rename
    fs::rename(&temp_path, path)
        .map_err(|e| VaultError::Io(format!("failed to rename temp file: {e}")))?;

    Ok(())
}

/// Check if a vault file exists at the given path.
pub fn vault_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use passman_types::{EncryptedBlob, KdfParams};

    fn test_vault() -> VaultFile {
        VaultFile {
            version: 1,
            kdf_params: KdfParams::default(),
            salt: vec![0u8; 32],
            verification: EncryptedBlob {
                nonce: vec![0u8; 12],
                ciphertext: vec![1, 2, 3],
            },
            credentials: vec![],
            categories: vec![],
            policies: vec![],
        }
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let vault = test_vault();
        save_vault(&path, &vault).unwrap();

        let loaded = load_vault(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.credentials.len(), 0);
    }

    #[test]
    fn test_vault_exists_false() {
        assert!(!vault_exists(Path::new("/nonexistent/vault.json")));
    }

    #[test]
    fn test_vault_exists_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        save_vault(&path, &test_vault()).unwrap();
        assert!(vault_exists(&path));
    }
}
