use base64::Engine;

/// Sanitize output by replacing all occurrences of secret values with `[REDACTED]`.
///
/// For each secret string (>= 4 chars), generates multiple encoding variants
/// (raw, base64, URL-encoded, hex) and replaces all occurrences.
pub fn sanitize(output: &str, secrets: &[String]) -> String {
    let mut result = output.to_string();

    for secret in secrets {
        if secret.len() < 4 {
            continue;
        }

        // Raw replacement
        result = result.replace(secret.as_str(), "[REDACTED]");

        // Base64-encoded variant
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        if b64.len() >= 4 {
            result = result.replace(&b64, "[REDACTED]");
        }

        // URL-safe base64
        let b64url = base64::engine::general_purpose::URL_SAFE.encode(secret.as_bytes());
        if b64url != b64 && b64url.len() >= 4 {
            result = result.replace(&b64url, "[REDACTED]");
        }

        // URL-encoded variant
        let urlenc = urlencoding::encode(secret);
        if urlenc != secret.as_str() && urlenc.len() >= 4 {
            result = result.replace(urlenc.as_ref(), "[REDACTED]");
        }

        // Hex-encoded variant (lowercase)
        let hexenc = hex::encode(secret.as_bytes());
        if hexenc.len() >= 4 {
            result = result.replace(&hexenc, "[REDACTED]");
        }

        // Hex-encoded variant (uppercase)
        let hexenc_upper = hexenc.to_uppercase();
        if hexenc_upper != hexenc {
            result = result.replace(&hexenc_upper, "[REDACTED]");
        }
    }

    result
}

/// Sanitize HTTP headers: remove sensitive header values.
pub fn sanitize_headers(
    headers: &[(String, String)],
    secrets: &[String],
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.clone(), sanitize(v, secrets)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_raw() {
        let secrets = vec!["mysecrettoken".to_string()];
        let output = "Response: mysecrettoken was used";
        assert_eq!(sanitize(output, &secrets), "Response: [REDACTED] was used");
    }

    #[test]
    fn test_sanitize_base64() {
        let secret = "mysecrettoken";
        let secrets = vec![secret.to_string()];
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let output = format!("Header: {b64}");
        assert_eq!(sanitize(&output, &secrets), "Header: [REDACTED]");
    }

    #[test]
    fn test_sanitize_url_encoded() {
        let secret = "my secret&token";
        let secrets = vec![secret.to_string()];
        let urlenc = urlencoding::encode(secret);
        let output = format!("URL: https://example.com?key={urlenc}");
        let result = sanitize(&output, &secrets);
        assert!(!result.contains(secret));
        assert!(!result.contains(urlenc.as_ref()));
    }

    #[test]
    fn test_sanitize_hex() {
        let secret = "mykey";
        let secrets = vec![secret.to_string()];
        let hexenc = hex::encode(secret.as_bytes());
        let output = format!("Data: {hexenc}");
        assert_eq!(sanitize(&output, &secrets), "Data: [REDACTED]");
    }

    #[test]
    fn test_skip_short_secrets() {
        let secrets = vec!["ab".to_string()];
        let output = "This has ab in it";
        // Short secrets are skipped to avoid false positives
        assert_eq!(sanitize(output, &secrets), output);
    }

    #[test]
    fn test_multiple_secrets() {
        let secrets = vec!["secret1".to_string(), "secret2".to_string()];
        let output = "Found secret1 and secret2 here";
        let result = sanitize(output, &secrets);
        assert_eq!(result, "Found [REDACTED] and [REDACTED] here");
    }

    #[test]
    fn test_sanitize_headers() {
        let secrets = vec!["Bearer mytoken123".to_string(), "mytoken123".to_string()];
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Authorization".to_string(),
                "Bearer mytoken123".to_string(),
            ),
        ];
        let sanitized = sanitize_headers(&headers, &secrets);
        assert_eq!(sanitized[0].1, "application/json");
        assert_eq!(sanitized[1].1, "[REDACTED]");
    }
}
