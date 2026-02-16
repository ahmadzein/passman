use passman_types::CredentialSecret;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::sanitizer;
use crate::ProxyError;

#[derive(Debug, Deserialize)]
pub struct HttpRequestInput {
    pub method: String,
    pub url: String,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Execute an HTTP request using the credential for authentication.
pub async fn execute(
    secret: &CredentialSecret,
    input: &HttpRequestInput,
) -> Result<HttpResponse, ProxyError> {
    let client = reqwest::Client::new();

    let method: reqwest::Method = input
        .method
        .parse()
        .map_err(|_| ProxyError::InvalidInput(format!("invalid HTTP method: {}", input.method)))?;

    let mut request = client.request(method, &input.url);

    // Build custom headers
    let mut header_map = HeaderMap::new();
    if let Some(headers) = &input.headers {
        for (k, v) in headers {
            let name = HeaderName::try_from(k.as_str())
                .map_err(|e| ProxyError::InvalidInput(format!("invalid header name '{k}': {e}")))?;
            let value = HeaderValue::try_from(v.as_str())
                .map_err(|e| ProxyError::InvalidInput(format!("invalid header value: {e}")))?;
            header_map.insert(name, value);
        }
    }

    // Inject authentication from the credential
    match secret {
        CredentialSecret::ApiToken {
            token,
            header_name,
            prefix,
        } => {
            let hdr_name = header_name.as_deref().unwrap_or("Authorization");
            let hdr_prefix = prefix.as_deref().unwrap_or("Bearer ");
            let value = format!("{hdr_prefix}{token}");

            let name = HeaderName::try_from(hdr_name)
                .map_err(|e| ProxyError::InvalidInput(format!("invalid header name: {e}")))?;
            let val = HeaderValue::try_from(&value)
                .map_err(|e| ProxyError::InvalidInput(format!("invalid header value: {e}")))?;
            header_map.insert(name, val);
        }
        CredentialSecret::Password {
            username, password, ..
        } => {
            request = request.basic_auth(username, Some(password));
        }
        CredentialSecret::Certificate {
            cert_pem, key_pem, ..
        } => {
            // mTLS: build a new client with the certificate identity
            let mut pem_bundle = cert_pem.as_bytes().to_vec();
            pem_bundle.push(b'\n');
            pem_bundle.extend_from_slice(key_pem.as_bytes());
            let identity = reqwest::Identity::from_pem(&pem_bundle)
                .map_err(|e| ProxyError::InvalidInput(format!("invalid certificate/key PEM: {e}")))?;

            let tls_client = reqwest::Client::builder()
                .identity(identity)
                .build()
                .map_err(|e| ProxyError::Protocol(format!("failed to build TLS client: {e}")))?;

            // Re-build the request with the mTLS client
            let method_clone: reqwest::Method = input
                .method
                .parse()
                .map_err(|_| ProxyError::InvalidInput(format!("invalid HTTP method: {}", input.method)))?;
            let mut cert_request = tls_client.request(method_clone, &input.url);
            cert_request = cert_request.headers(header_map);
            if let Some(body) = &input.body {
                cert_request = cert_request.body(body.clone());
            }

            let response = cert_request
                .send()
                .await
                .map_err(|e| ProxyError::Protocol(format!("HTTP request failed: {e}")))?;

            let status = response.status().as_u16();
            let resp_headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = response
                .text()
                .await
                .map_err(|e| ProxyError::Protocol(format!("failed to read response body: {e}")))?;

            let secrets = secret.secret_strings();
            let sanitized_body = sanitizer::sanitize(&body, &secrets);
            let sanitized_headers: HashMap<String, String> = resp_headers
                .into_iter()
                .map(|(k, v)| (k, sanitizer::sanitize(&v, &secrets)))
                .collect();

            return Ok(HttpResponse {
                status,
                headers: sanitized_headers,
                body: sanitized_body,
            });
        }
        _ => {
            return Err(ProxyError::InvalidInput(
                "credential type not supported for HTTP requests".to_string(),
            ));
        }
    }

    request = request.headers(header_map);

    if let Some(body) = &input.body {
        request = request.body(body.clone());
    }

    let response = request
        .send()
        .await
        .map_err(|e| ProxyError::Protocol(format!("HTTP request failed: {e}")))?;

    let status = response.status().as_u16();

    let resp_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = response
        .text()
        .await
        .map_err(|e| ProxyError::Protocol(format!("failed to read response body: {e}")))?;

    // Sanitize the response
    let secrets = secret.secret_strings();
    let sanitized_body = sanitizer::sanitize(&body, &secrets);
    let sanitized_headers: HashMap<String, String> = resp_headers
        .into_iter()
        .map(|(k, v)| (k, sanitizer::sanitize(&v, &secrets)))
        .collect();

    Ok(HttpResponse {
        status,
        headers: sanitized_headers,
        body: sanitized_body,
    })
}
