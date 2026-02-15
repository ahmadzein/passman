use passman_types::AuditEntry;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::VaultError;

/// Append an audit entry to the JSONL audit log file.
pub fn append_entry(path: &Path, entry: &AuditEntry) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VaultError::Io(format!("failed to create audit dir: {e}")))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| VaultError::Io(format!("failed to open audit log: {e}")))?;

    let line = serde_json::to_string(entry)
        .map_err(|e| VaultError::Io(format!("failed to serialize audit entry: {e}")))?;

    writeln!(file, "{line}")
        .map_err(|e| VaultError::Io(format!("failed to write audit entry: {e}")))?;

    Ok(())
}

/// Read audit entries from the JSONL log, with optional filters.
pub fn read_entries(
    path: &Path,
    credential_id: Option<uuid::Uuid>,
    limit: Option<usize>,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<AuditEntry>, VaultError> {
    if !path.exists() {
        return Ok(vec![]);
    }

    let contents = fs::read_to_string(path)
        .map_err(|e| VaultError::Io(format!("failed to read audit log: {e}")))?;

    let mut entries: Vec<AuditEntry> = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .filter(|entry: &AuditEntry| {
            if let Some(cid) = credential_id {
                if entry.credential_id != Some(cid) {
                    return false;
                }
            }
            if let Some(ref s) = since {
                if entry.timestamp < *s {
                    return false;
                }
            }
            true
        })
        .collect();

    // Most recent first
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if let Some(lim) = limit {
        entries.truncate(lim);
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use passman_types::AuditAction;
    use uuid::Uuid;

    fn test_entry(cred_id: Option<Uuid>) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            credential_id: cred_id,
            credential_name: Some("test".to_string()),
            action: AuditAction::HttpRequest,
            tool: "http_request".to_string(),
            success: true,
            details: None,
        }
    }

    #[test]
    fn test_append_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let id = Uuid::new_v4();
        append_entry(&path, &test_entry(Some(id))).unwrap();
        append_entry(&path, &test_entry(None)).unwrap();

        let all = read_entries(&path, None, None, None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = read_entries(&path, Some(id), None, None).unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_read_nonexistent() {
        let entries = read_entries(Path::new("/nonexistent/audit.jsonl"), None, None, None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        for _ in 0..10 {
            append_entry(&path, &test_entry(None)).unwrap();
        }

        let limited = read_entries(&path, None, Some(3), None).unwrap();
        assert_eq!(limited.len(), 3);
    }
}
