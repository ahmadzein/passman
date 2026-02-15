use passman_types::PolicyRule;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Policy engine that evaluates per-credential rules and rate limits.
pub struct PolicyEngine {
    rate_counters: Mutex<HashMap<Uuid, Vec<Instant>>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rate_counters: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a tool is allowed for the given credential.
    pub fn check_tool(&self, policy: &PolicyRule, tool_name: &str) -> Result<(), PolicyDenied> {
        if !policy.allowed_tools.is_empty()
            && !policy.allowed_tools.iter().any(|t| t == tool_name)
        {
            return Err(PolicyDenied(format!(
                "tool '{}' not allowed for this credential",
                tool_name
            )));
        }
        Ok(())
    }

    /// Check if a URL matches the HTTP URL patterns.
    pub fn check_http_url(&self, policy: &PolicyRule, url: &str) -> Result<(), PolicyDenied> {
        if policy.http_url_patterns.is_empty() {
            return Ok(());
        }

        for pattern in &policy.http_url_patterns {
            if url_matches_pattern(url, pattern) {
                return Ok(());
            }
        }

        Err(PolicyDenied(format!(
            "URL '{}' not allowed by policy",
            url
        )))
    }

    /// Check if an SSH command matches allowed patterns.
    pub fn check_ssh_command(
        &self,
        policy: &PolicyRule,
        command: &str,
    ) -> Result<(), PolicyDenied> {
        if policy.ssh_command_patterns.is_empty() {
            return Ok(());
        }

        for pattern in &policy.ssh_command_patterns {
            if command_matches_pattern(command, pattern) {
                return Ok(());
            }
        }

        Err(PolicyDenied(format!(
            "SSH command not allowed by policy"
        )))
    }

    /// Check if a SQL query is allowed (read-only enforcement).
    pub fn check_sql_query(&self, policy: &PolicyRule, query: &str) -> Result<(), PolicyDenied> {
        if policy.sql_allow_write {
            return Ok(());
        }

        let trimmed = query.trim().to_uppercase();
        let write_keywords = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "REPLACE", "MERGE"];

        for keyword in &write_keywords {
            if trimmed.starts_with(keyword) {
                return Err(PolicyDenied(format!(
                    "write queries not allowed for this credential (starts with {})",
                    keyword
                )));
            }
        }

        Ok(())
    }

    /// Check if an email recipient is allowed.
    pub fn check_smtp_recipient(
        &self,
        policy: &PolicyRule,
        recipient: &str,
    ) -> Result<(), PolicyDenied> {
        if policy.smtp_allowed_recipients.is_empty() {
            return Ok(());
        }

        for pattern in &policy.smtp_allowed_recipients {
            if email_matches_pattern(recipient, pattern) {
                return Ok(());
            }
        }

        Err(PolicyDenied(format!(
            "recipient '{}' not allowed by policy",
            recipient
        )))
    }

    /// Check and increment the rate limit counter.
    pub async fn check_rate_limit(&self, policy: &PolicyRule) -> Result<(), PolicyDenied> {
        let rate_limit = match &policy.rate_limit {
            Some(rl) => rl,
            None => return Ok(()),
        };

        let mut counters = self.rate_counters.lock().await;
        let entries = counters
            .entry(policy.credential_id)
            .or_insert_with(Vec::new);

        let window = std::time::Duration::from_secs(rate_limit.window_secs);
        let now = Instant::now();

        // Remove expired entries
        entries.retain(|t| now.duration_since(*t) < window);

        if entries.len() >= rate_limit.max_requests as usize {
            return Err(PolicyDenied(format!(
                "rate limit exceeded: {}/{} requests in {} seconds",
                entries.len(),
                rate_limit.max_requests,
                rate_limit.window_secs
            )));
        }

        entries.push(now);
        Ok(())
    }
}

#[derive(Debug)]
pub struct PolicyDenied(pub String);

impl std::fmt::Display for PolicyDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy denied: {}", self.0)
    }
}

/// Simple wildcard pattern matching for URLs (supports * as glob).
fn url_matches_pattern(url: &str, pattern: &str) -> bool {
    glob_match(url, pattern)
}

/// Simple wildcard pattern matching for SSH commands.
fn command_matches_pattern(command: &str, pattern: &str) -> bool {
    glob_match(command, pattern)
}

/// Simple wildcard pattern matching for email addresses.
fn email_matches_pattern(email: &str, pattern: &str) -> bool {
    glob_match(email, pattern)
}

/// Basic glob matching with * wildcard support.
fn glob_match(text: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        return text == pattern;
    }

    let mut pos = 0;

    // First part must match the beginning
    if let Some(first) = parts.first() {
        if !first.is_empty() {
            if !text.starts_with(first) {
                return false;
            }
            pos = first.len();
        }
    }

    // Last part must match the end
    if let Some(last) = parts.last() {
        if !last.is_empty() && !text.ends_with(last) {
            return false;
        }
    }

    // Middle parts must appear in order
    for part in &parts[1..parts.len().saturating_sub(1)] {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("https://api.github.com/repos", "https://api.github.com/*"));
        assert!(glob_match("ls -la /tmp", "ls *"));
        assert!(glob_match("user@company.com", "*@company.com"));
        assert!(!glob_match("user@other.com", "*@company.com"));
        assert!(glob_match("anything", "*"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("different", "exact"));
    }

    #[test]
    fn test_sql_read_only() {
        let engine = PolicyEngine::new();
        let policy = PolicyRule {
            credential_id: Uuid::new_v4(),
            allowed_tools: vec![],
            http_url_patterns: vec![],
            ssh_command_patterns: vec![],
            sql_allow_write: false,
            smtp_allowed_recipients: vec![],
            rate_limit: None,
        };

        assert!(engine.check_sql_query(&policy, "SELECT * FROM users").is_ok());
        assert!(engine.check_sql_query(&policy, "select count(*) from users").is_ok());
        assert!(engine.check_sql_query(&policy, "INSERT INTO users VALUES (1)").is_err());
        assert!(engine.check_sql_query(&policy, "DELETE FROM users").is_err());
        assert!(engine.check_sql_query(&policy, "DROP TABLE users").is_err());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let engine = PolicyEngine::new();
        let policy = PolicyRule {
            credential_id: Uuid::new_v4(),
            allowed_tools: vec![],
            http_url_patterns: vec![],
            ssh_command_patterns: vec![],
            sql_allow_write: false,
            smtp_allowed_recipients: vec![],
            rate_limit: Some(passman_types::RateLimit {
                max_requests: 2,
                window_secs: 3600,
            }),
        };

        assert!(engine.check_rate_limit(&policy).await.is_ok());
        assert!(engine.check_rate_limit(&policy).await.is_ok());
        assert!(engine.check_rate_limit(&policy).await.is_err()); // exceeded
    }
}
