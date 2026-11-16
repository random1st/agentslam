//! feat.agentslam-join-mail: the room owner gets an email about a new join request.

mod common;

use std::sync::Arc;
use std::time::Duration;

use agentslam::core::config::{MailConfig, MailTls};
use common::Env;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Minimal plain-text SMTP sink: accepts every message, records (rcpt, data).
struct SmtpSink {
    port: u16,
    got: Arc<Mutex<Vec<(String, String)>>>,
}

impl SmtpSink {
    async fn start() -> SmtpSink {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
        let port = l.local_addr().expect("addr").port();
        let got: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let g = got.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = l.accept().await {
                let g = g.clone();
                tokio::spawn(async move {
                    let (r, mut w) = sock.into_split();
                    let mut r = BufReader::new(r);
                    w.write_all(b"220 sink ESMTP\r\n").await.ok();
                    let (mut rcpt, mut data, mut in_data) = (String::new(), String::new(), false);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        if in_data {
                            if line == ".\r\n" {
                                in_data = false;
                                g.lock().await.push((rcpt.clone(), data.clone()));
                                w.write_all(b"250 queued\r\n").await.ok();
                            } else {
                                data.push_str(&line);
                            }
                            continue;
                        }
                        let up = line.to_ascii_uppercase();
                        let reply: &[u8] = if up.starts_with("EHLO") || up.starts_with("HELO") {
                            b"250 sink\r\n"
                        } else if up.starts_with("RCPT TO:") {
                            rcpt = line[8..].trim().trim_matches(['<', '>']).to_string();
                            b"250 ok\r\n"
                        } else if up.starts_with("DATA") {
                            in_data = true;
                            data.clear();
                            b"354 go\r\n"
                        } else if up.starts_with("QUIT") {
                            w.write_all(b"221 bye\r\n").await.ok();
                            break;
                        } else {
                            b"250 ok\r\n"
                        };
                        w.write_all(reply).await.ok();
                    }
                });
            }
        });
        SmtpSink { port, got }
    }

    async fn wait_count(&self, n: usize) -> Vec<(String, String)> {
        for _ in 0..100 {
            let v = self.got.lock().await.clone();
            if v.len() >= n {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.got.lock().await.clone()
    }
}

fn mail_to(port: u16) -> MailConfig {
    MailConfig {
        host: "127.0.0.1".into(),
        port,
        username: String::new(),
        from: "agentslam <agentslam@example.com>".into(),
        tls: MailTls::None,
        password: None,
    }
}

#[tokio::test]
async fn s5d_ac_uc_agentslam_join_mail_new_request_mails_owner() {
    let sink = SmtpSink::start().await;
    let port = sink.port;
    let env = Env::start_with(move |c| c.mail = Some(mail_to(port))).await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    let r = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(r["status"], json!("pending"));
    let got = sink.wait_count(1).await;
    assert_eq!(got.len(), 1, "one email for a new request: {got:?}");
    let (rcpt, data) = &got[0];
    assert_eq!(rcpt, "roman@example.com");
    assert!(data.contains("alex/codex"), "names the agent: {data}");
    assert!(data.contains("ios"), "names the room: {data}");
    assert!(
        data.contains("/?room=ios#requests"),
        "has the web UI link: {data}"
    );

    // A repeat while pending sends nothing more.
    let r = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(r["status"], json!("pending"));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        sink.got.lock().await.len(),
        1,
        "no second email for a repeat"
    );

    // The owner's own agent is admitted at once, no email.
    let roman2 = env.agent("roman", "codex").await;
    let r = roman2.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(r["status"], json!("member"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        sink.got.lock().await.len(),
        1,
        "no email for an at-once admission"
    );
}

#[tokio::test]
async fn s5d_ac_uc_agentslam_join_mail_no_mail_config() {
    let env = Env::start().await;
    assert!(env.server.state.mailer.is_none());
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    let r = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(r["status"], json!("pending"));
}

#[tokio::test]
async fn s5d_ac_uc_agentslam_join_mail_send_failure_isolated() {
    // A port nobody listens on: bind, take the port, drop the listener.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let env = Env::start_with(move |c| c.mail = Some(mail_to(port))).await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    let started = std::time::Instant::now();
    let r = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(r["status"], json!("pending"));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "join is not held by the mail send"
    );
}

#[test]
fn mail_tls_none_needs_test_flag() {
    let mut c = agentslam::core::config::Config::from_toml(
        "public_url = \"http://127.0.0.1:8787\"\n[mail]\nhost = \"smtp.example.com\"\nfrom = \"a@example.com\"\ntls = \"none\"\n",
    )
    .expect("parse");
    assert!(
        c.validate().is_err(),
        "plain-text SMTP refused outside tests"
    );
    c.mail.as_mut().expect("mail").tls = MailTls::Starttls;
    c.validate().expect("starttls accepted");
    c.mail.as_mut().expect("mail").from = "not an address".into();
    assert!(c.validate().is_err(), "bad from refused");
}
