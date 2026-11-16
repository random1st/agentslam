//! Outbound email: a notice to the room owner about a new join request.
//! Sent in a background task after the request is committed. A failure is
//! logged and never reaches the agent that asked to join.

use std::time::Duration;

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::core::config::{MailConfig, MailTls};

pub struct Mailer {
    from: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

/// One join request notice, built inside the request transaction.
#[derive(Debug, Clone)]
pub struct JoinNotice {
    pub to: String,
    pub agent: String,
    pub room: String,
    pub link: String,
}

impl Mailer {
    pub fn new(cfg: &MailConfig) -> anyhow::Result<Mailer> {
        let from: Mailbox = cfg
            .from
            .parse()
            .map_err(|e| anyhow::anyhow!("mail.from: {e}"))?;
        let mut b = match cfg.tls {
            MailTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?,
            MailTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?,
            MailTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
        };
        b = b.port(cfg.port).timeout(Some(Duration::from_secs(15)));
        if !cfg.username.is_empty() {
            b = b.credentials(Credentials::new(
                cfg.username.clone(),
                cfg.password.clone().unwrap_or_default(),
            ));
        }
        Ok(Mailer {
            from,
            transport: b.build(),
        })
    }

    pub async fn send_join_notice(&self, n: &JoinNotice) -> anyhow::Result<()> {
        let to: Mailbox =
            n.to.parse()
                .map_err(|e| anyhow::anyhow!("owner address {:?}: {e}", n.to))?;
        let body = format!(
            "{agent} asks to join your agentslam room {room}.\n\n\
             Only you decide. Confirm or decline here:\n{link}\n\n\
             The request expires if nobody decides it.\n",
            agent = n.agent,
            room = n.room,
            link = n.link,
        );
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(format!("{} asks to join room {}", n.agent, n.room))
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;
        self.transport.send(msg).await?;
        Ok(())
    }
}

/// Send in the background. Never blocks or fails the caller.
pub fn spawn_join_notice(mailer: std::sync::Arc<Mailer>, n: JoinNotice) {
    tokio::spawn(async move {
        match mailer.send_join_notice(&n).await {
            Ok(()) => tracing::info!(room = %n.room, agent = %n.agent, "join request email sent"),
            Err(e) => {
                tracing::warn!(room = %n.room, agent = %n.agent, error = %e, "join request email failed")
            }
        }
    });
}
