//! Integration test: full vault lifecycle.
//!
//! Tests: create vault -> unlock -> store credential -> list -> search
//!        -> policy CRUD -> delete -> lock -> re-unlock

use passman_types::{CredentialKind, CredentialSecret, Environment, PolicyRule};
use passman_vault::Vault;
use tempfile::TempDir;

fn setup() -> (Vault, TempDir) {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.json");
    let audit_path = dir.path().join("audit.jsonl");
    let vault = Vault::new(vault_path, audit_path);
    (vault, dir)
}

#[tokio::test]
async fn test_full_lifecycle() {
    let (vault, _dir) = setup();
    let password = "integration-test-pw-2024";

    // ── 1. Create vault ─────────────────────────────────────
    assert!(!vault.exists().await);
    vault.create(password).await.unwrap();
    assert!(vault.exists().await);
    assert!(vault.is_unlocked().await);
    assert_eq!(vault.credential_count().await.unwrap(), 0);

    // ── 2. Store credentials ────────────────────────────────
    let api_id = vault
        .store_credential(
            "GitHub Token".into(),
            CredentialKind::ApiToken,
            Environment::Development,
            vec!["github".into(), "ci".into()],
            Some("Main GitHub PAT".into()),
            &CredentialSecret::ApiToken {
                token: "ghp_test123456789".into(),
                header_name: Some("Authorization".into()),
                prefix: Some("Bearer ".into()),
            },
        )
        .await
        .unwrap();

    let db_id = vault
        .store_credential(
            "Prod Postgres".into(),
            CredentialKind::DatabaseConnection,
            Environment::Production,
            vec!["database".into()],
            None,
            &CredentialSecret::DatabaseConnection {
                driver: passman_types::DbDriver::Postgres,
                host: "db.example.com".into(),
                port: 5432,
                database: "myapp".into(),
                username: "admin".into(),
                password: "super-secret-db-pw".into(),
                params: Default::default(),
            },
        )
        .await
        .unwrap();

    assert_eq!(vault.credential_count().await.unwrap(), 2);

    // ── 3. List & filter ────────────────────────────────────
    let all = vault.list_credentials(None, None, None).await.unwrap();
    assert_eq!(all.len(), 2);

    let api_only = vault
        .list_credentials(Some(CredentialKind::ApiToken), None, None)
        .await
        .unwrap();
    assert_eq!(api_only.len(), 1);
    assert_eq!(api_only[0].name, "GitHub Token");

    let prod_only = vault
        .list_credentials(None, Some(Environment::Production), None)
        .await
        .unwrap();
    assert_eq!(prod_only.len(), 1);
    assert_eq!(prod_only[0].name, "Prod Postgres");

    let tag_filter = vault
        .list_credentials(None, None, Some("ci".into()))
        .await
        .unwrap();
    assert_eq!(tag_filter.len(), 1);

    // ── 4. Search ───────────────────────────────────────────
    let search = vault.search_credentials("github").await.unwrap();
    assert_eq!(search.len(), 1);

    let search2 = vault.search_credentials("postgres").await.unwrap();
    assert_eq!(search2.len(), 1);

    // ── 5. Get metadata & secret ────────────────────────────
    let meta = vault.get_credential_meta(api_id).await.unwrap();
    assert_eq!(meta.name, "GitHub Token");
    assert_eq!(meta.kind, CredentialKind::ApiToken);

    let secret = vault.get_credential_secret(api_id).await.unwrap();
    match &secret {
        CredentialSecret::ApiToken { token, .. } => {
            assert_eq!(token, "ghp_test123456789");
        }
        _ => panic!("Expected ApiToken secret"),
    }

    // ── 6. Policy CRUD ──────────────────────────────────────
    assert!(vault.get_policy(api_id).await.unwrap().is_none());

    let policy = PolicyRule {
        credential_id: api_id,
        allowed_tools: vec!["http_request".into()],
        http_url_patterns: vec!["https://api.github.com/*".into()],
        ssh_command_patterns: vec![],
        sql_allow_write: false,
        smtp_allowed_recipients: vec![],
        rate_limit: Some(passman_types::RateLimit {
            max_requests: 100,
            window_secs: 3600,
        }),
    };
    vault.save_policy(policy).await.unwrap();

    let saved = vault.get_policy(api_id).await.unwrap().unwrap();
    assert_eq!(saved.allowed_tools, vec!["http_request"]);
    assert_eq!(saved.http_url_patterns, vec!["https://api.github.com/*"]);
    assert!(saved.rate_limit.is_some());

    // Update policy
    let updated_policy = PolicyRule {
        credential_id: api_id,
        allowed_tools: vec!["http_request".into(), "ssh_exec".into()],
        http_url_patterns: vec!["https://api.github.com/*".into()],
        ssh_command_patterns: vec![],
        sql_allow_write: false,
        smtp_allowed_recipients: vec![],
        rate_limit: None,
    };
    vault.save_policy(updated_policy).await.unwrap();
    let saved2 = vault.get_policy(api_id).await.unwrap().unwrap();
    assert_eq!(saved2.allowed_tools.len(), 2);
    assert!(saved2.rate_limit.is_none());

    // Delete policy
    assert!(vault.delete_policy(api_id).await.unwrap());
    assert!(vault.get_policy(api_id).await.unwrap().is_none());
    assert!(!vault.delete_policy(api_id).await.unwrap()); // already deleted

    // ── 7. Environments ─────────────────────────────────────
    let envs = vault.get_environments().await.unwrap();
    assert!(envs.contains(&"development".to_string()));
    assert!(envs.contains(&"production".to_string()));

    // ── 8. Audit log ────────────────────────────────────────
    let audit = vault.read_audit(None, None, None).await.unwrap();
    assert!(audit.len() >= 2); // at least 2 store operations

    let api_audit = vault.read_audit(Some(api_id), None, None).await.unwrap();
    assert!(!api_audit.is_empty());

    // ── 9. Delete credential ────────────────────────────────
    assert!(vault.delete_credential(db_id).await.unwrap());
    assert_eq!(vault.credential_count().await.unwrap(), 1);
    assert!(!vault.delete_credential(db_id).await.unwrap()); // already deleted

    // ── 10. Lock & re-unlock ────────────────────────────────
    vault.lock().await;
    assert!(!vault.is_unlocked().await);

    // Should fail when locked
    assert!(vault.list_credentials(None, None, None).await.is_err());

    // Re-unlock
    let count = vault.unlock(password).await.unwrap();
    assert_eq!(count, 1); // only the API token remains
    assert!(vault.is_unlocked().await);

    // Verify data persisted across lock/unlock
    let remaining = vault.list_credentials(None, None, None).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].name, "GitHub Token");

    // Wrong password should fail
    vault.lock().await;
    assert!(vault.unlock("wrong-password").await.is_err());
}

#[tokio::test]
async fn test_vault_reload() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.json");
    let audit_path = dir.path().join("audit.jsonl");

    // Create and populate vault with instance A
    let vault_a = Vault::new(vault_path.clone(), audit_path.clone());
    vault_a.create("reload-test-pw").await.unwrap();
    vault_a
        .store_credential(
            "Test Cred".into(),
            CredentialKind::Password,
            Environment::Local,
            vec![],
            None,
            &CredentialSecret::Password {
                username: "user".into(),
                password: "pass".into(),
                url: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(vault_a.credential_count().await.unwrap(), 1);

    // Instance B opens the same vault
    let vault_b = Vault::new(vault_path.clone(), audit_path.clone());
    vault_b.unlock("reload-test-pw").await.unwrap();
    assert_eq!(vault_b.credential_count().await.unwrap(), 1);

    // A adds a credential
    vault_a
        .store_credential(
            "Another Cred".into(),
            CredentialKind::ApiToken,
            Environment::Development,
            vec![],
            None,
            &CredentialSecret::ApiToken {
                token: "tok".into(),
                header_name: None,
                prefix: None,
            },
        )
        .await
        .unwrap();

    // B still sees old count until reload
    assert_eq!(vault_b.credential_count().await.unwrap(), 1);

    // B reloads from disk
    vault_b.reload().await.unwrap();
    assert_eq!(vault_b.credential_count().await.unwrap(), 2);
}
