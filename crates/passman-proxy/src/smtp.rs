use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use passman_types::{CredentialSecret, SmtpEncryption};
use serde::{Deserialize, Serialize};

use crate::ProxyError;

#[derive(Debug, Deserialize)]
pub struct SendEmailInput {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    pub cc: Option<Vec<String>>,
    pub bcc: Option<Vec<String>>,
    pub from: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SendEmailOutput {
    pub success: bool,
    pub message_id: Option<String>,
}

fn parse_mailbox(addr: &str) -> Result<Mailbox, ProxyError> {
    addr.parse::<Mailbox>()
        .map_err(|e| ProxyError::InvalidInput(format!("invalid email address '{addr}': {e}")))
}

/// Send an email using the stored SMTP credential.
pub async fn execute(
    secret: &CredentialSecret,
    input: &SendEmailInput,
) -> Result<SendEmailOutput, ProxyError> {
    let (host, port, username, password, encryption) = match secret {
        CredentialSecret::SmtpAccount {
            host,
            port,
            username,
            password,
            encryption,
        } => (
            host.clone(),
            *port,
            username.clone(),
            password.clone(),
            *encryption,
        ),
        _ => {
            return Err(ProxyError::InvalidInput(
                "credential type not supported for SMTP".to_string(),
            ));
        }
    };

    let from_addr = if let Some(ref from) = input.from {
        parse_mailbox(from)?
    } else {
        parse_mailbox(&username)?
    };

    let mut builder = Message::builder().from(from_addr);

    for to in &input.to {
        builder = builder.to(parse_mailbox(to)?);
    }

    if let Some(ref cc_list) = input.cc {
        for cc in cc_list {
            builder = builder.cc(parse_mailbox(cc)?);
        }
    }

    if let Some(ref bcc_list) = input.bcc {
        for bcc in bcc_list {
            builder = builder.bcc(parse_mailbox(bcc)?);
        }
    }

    builder = builder.subject(&input.subject);

    let message = builder
        .body(input.body.clone())
        .map_err(|e| ProxyError::Protocol(format!("failed to build email message: {e}")))?;

    let creds = Credentials::new(username, password);

    let transport = match encryption {
        SmtpEncryption::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
            .map_err(|e| ProxyError::Protocol(format!("SMTP TLS connection failed: {e}")))?
            .port(port)
            .credentials(creds)
            .build(),
        SmtpEncryption::StartTls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                .map_err(|e| {
                    ProxyError::Protocol(format!("SMTP STARTTLS connection failed: {e}"))
                })?
                .port(port)
                .credentials(creds)
                .build()
        }
        SmtpEncryption::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
            .port(port)
            .credentials(creds)
            .build(),
    };

    let response = transport
        .send(message)
        .await
        .map_err(|e| ProxyError::Protocol(format!("failed to send email: {e}")))?;

    let success = response.is_positive();
    let message_id: Option<String> = response.message().next().map(|s| s.to_string());
    Ok(SendEmailOutput {
        success,
        message_id,
    })
}
