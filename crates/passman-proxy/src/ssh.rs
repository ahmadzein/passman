use passman_types::CredentialSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::sanitizer;
use crate::ProxyError;

#[derive(Debug, Deserialize)]
pub struct SshExecInput {
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct SshExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

struct SshClientHandler;

#[async_trait::async_trait]
impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all host keys (the user has explicitly configured the host).
        Ok(true)
    }
}

/// Execute an SSH command using the stored credential.
pub async fn execute(
    secret: &CredentialSecret,
    input: &SshExecInput,
) -> Result<SshExecOutput, ProxyError> {
    let (username, host, port, key_data, passphrase) = match secret {
        CredentialSecret::SshKey {
            username,
            host,
            port,
            private_key,
            passphrase,
        } => (
            username.clone(),
            host.clone(),
            *port,
            Some(private_key.clone()),
            passphrase.clone(),
        ),
        CredentialSecret::SshPassword {
            username,
            host,
            port,
            password,
        } => (username.clone(), host.clone(), *port, None, Some(password.clone())),
        CredentialSecret::Password {
            username, password, url, ..
        } => {
            let host = url.as_deref().unwrap_or("localhost").to_string();
            (username.clone(), host, 22, None, Some(password.clone()))
        }
        _ => {
            return Err(ProxyError::InvalidInput(
                "credential type not supported for SSH".to_string(),
            ));
        }
    };

    let config = Arc::new(russh::client::Config::default());
    let handler = SshClientHandler;

    let mut session = russh::client::connect(config, (host.as_str(), port), handler)
        .await
        .map_err(|e| ProxyError::Protocol(format!("SSH connection failed: {e}")))?;

    // Authenticate
    if let Some(ref key_str) = key_data {
        let key_pair = if let Some(ref pass) = passphrase {
            russh_keys::decode_secret_key(key_str, Some(pass))
                .map_err(|e| ProxyError::Protocol(format!("failed to decode SSH key: {e}")))?
        } else {
            russh_keys::decode_secret_key(key_str, None)
                .map_err(|e| ProxyError::Protocol(format!("failed to decode SSH key: {e}")))?
        };

        let authenticated = session
            .authenticate_publickey(&username, Arc::new(key_pair))
            .await
            .map_err(|e| ProxyError::Protocol(format!("SSH public key auth failed: {e}")))?;

        if !authenticated {
            return Err(ProxyError::Protocol(
                "SSH authentication rejected".to_string(),
            ));
        }
    } else if let Some(ref pass) = passphrase {
        let authenticated = session
            .authenticate_password(&username, pass)
            .await
            .map_err(|e| ProxyError::Protocol(format!("SSH password auth failed: {e}")))?;

        if !authenticated {
            return Err(ProxyError::Protocol(
                "SSH authentication rejected".to_string(),
            ));
        }
    }

    // Execute command
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| ProxyError::Protocol(format!("failed to open SSH channel: {e}")))?;

    channel
        .exec(true, input.command.as_str())
        .await
        .map_err(|e| ProxyError::Protocol(format!("failed to exec SSH command: {e}")))?;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut exit_code: i32 = -1;

    // Inactivity timeout: resets every time we receive data.
    // Commands that keep producing output can run indefinitely.
    // Commands that go silent for 120s are considered hung.
    let inactivity = std::time::Duration::from_secs(120);
    let mut deadline = tokio::time::Instant::now() + inactivity;

    loop {
        let msg = tokio::time::timeout_at(deadline, channel.wait()).await;
        match msg {
            Ok(Some(msg)) => match msg {
                russh::ChannelMsg::Data { ref data } => {
                    stdout_buf.extend_from_slice(data);
                    deadline = tokio::time::Instant::now() + inactivity;
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr_buf.extend_from_slice(data);
                    }
                    deadline = tokio::time::Instant::now() + inactivity;
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status as i32;
                }
                _ => {}
            },
            Ok(None) => break,
            Err(_) => {
                // No data received for 120s - command is likely hung
                stderr_buf.extend_from_slice(
                    b"\n[passman: SSH command timed out - no output for 120s, output may be partial]",
                );
                break;
            }
        }
    }

    session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    let secrets = secret.secret_strings();
    let stdout = sanitizer::sanitize(&String::from_utf8_lossy(&stdout_buf), &secrets);
    let stderr = sanitizer::sanitize(&String::from_utf8_lossy(&stderr_buf), &secrets);

    Ok(SshExecOutput {
        exit_code,
        stdout,
        stderr,
    })
}
