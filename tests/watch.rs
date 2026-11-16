//! feat.agentslam-watch: a monitored watch stream wakes an idle agent.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

/// Read the stream until `needle` shows up (Some(all read)) or `within` passes (None).
async fn read_until(
    resp: &mut reqwest::Response,
    needle: &str,
    within: Duration,
) -> Option<String> {
    let deadline = Instant::now() + within;
    let mut buf = String::new();
    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, resp.chunk()).await {
            Ok(Ok(Some(bytes))) => {
                buf.push_str(&String::from_utf8_lossy(&bytes));
                if buf.contains(needle) {
                    return Some(buf);
                }
            }
            _ => break,
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_watch_item_wakes_watch() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    let att = roman
        .ok("room_attach", json!({"room": "ios", "session": "W"}))
        .await;
    let url = att["watch"]["url"].as_str().expect("watch url").to_string();
    let cmd = att["watch"]["command"].as_str().expect("watch command");
    assert!(
        cmd.contains(&url) && cmd.contains("until curl -sfN "),
        "{cmd}"
    );
    assert!(url.starts_with(&format!("{}/watch/", env.base)), "{url}");

    let mut stream = reqwest::get(&url).await.expect("open watch");
    assert_eq!(stream.status(), 200);
    // A first byte at once, so proxies pass the headers without waiting for a keepalive.
    assert!(
        read_until(&mut stream, ": connected\n", Duration::from_secs(2))
            .await
            .is_some(),
        "first line arrives immediately"
    );
    assert!(
        read_until(&mut stream, "agentslam:", Duration::from_millis(600))
            .await
            .is_none(),
        "no notice before anything happens"
    );

    alex.ok("room_send", json!({"room": "ios", "text": "secret plan"}))
        .await;
    let got = read_until(&mut stream, "\n", Duration::from_secs(5))
        .await
        .expect("notice for the new item");
    assert!(
        got.contains("agentslam: new room items (1 in ios; 1 unread in total)"),
        "{got}"
    );
    assert!(got.contains("room_wait with session \"W\""), "{got}");
    assert!(
        !got.contains("secret plan"),
        "the stream carries no room content: {got}"
    );

    alex.ok("room_send", json!({"room": "ios", "text": "second"}))
        .await;
    let got = read_until(&mut stream, "\n", Duration::from_secs(5))
        .await
        .expect("notice for the second item");
    assert!(
        got.contains("(1 in ios; 2 unread in total)"),
        "only the new one is counted: {got}"
    );

    // Reading with room_wait moves the cursor; nothing new, no notice.
    let w = roman
        .ok("room_wait", json!({"session": "W", "timeout_s": 1}))
        .await;
    assert_eq!(w["messages"].as_array().map(Vec::len), Some(2));
    assert!(
        read_until(&mut stream, "agentslam:", Duration::from_millis(600))
            .await
            .is_none(),
        "no repeat after reading"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_watch_bad_link_or_no_rooms() {
    let env = Env::start().await;
    let (roman, _alex) = env.ios_with_alex().await;
    let att = roman
        .ok("room_attach", json!({"room": "ios", "session": "W"}))
        .await;
    let url = att["watch"]["url"].as_str().expect("url").to_string();

    // Another session or agent in the path does not match the signature.
    // Refused as a 200 with a reason line (the monitor retries HTTP errors).
    let refused = |body: String| body.starts_with("agentslam: this watch link is not valid");
    let forged = url.replacen("/W/", "/X/", 1);
    let r = reqwest::get(&forged).await.expect("get");
    assert_eq!(r.status(), 200);
    assert!(
        refused(r.text().await.expect("body")),
        "forged link refused"
    );
    // Flip the last hex digit to a different one (a fixed "0" left 1 in 16 links intact).
    let last = if url.ends_with('0') { '1' } else { '0' };
    let tampered = format!("{}{last}", &url[..url.len() - 1]);
    assert_ne!(tampered, url);
    let r = reqwest::get(&tampered).await.expect("get");
    assert_eq!(r.status(), 200);
    assert!(
        refused(r.text().await.expect("body")),
        "tampered link refused"
    );

    // After detaching, the stream says why and ends.
    roman
        .ok("room_detach", json!({"room": "ios", "session": "W"}))
        .await;
    let mut stream = reqwest::get(&url).await.expect("open");
    let got = read_until(&mut stream, "session W.", Duration::from_secs(5))
        .await
        .expect("reason line");
    assert!(
        got.contains("agentslam: no rooms attached to session W"),
        "{got}"
    );
    let end = tokio::time::timeout(Duration::from_secs(5), stream.chunk())
        .await
        .expect("stream ends");
    assert!(matches!(end, Ok(None)), "stream closed after the reason");
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_link_survives_restart_key() {
    // The key is stored, so the same (agent, session) gets the same link.
    let env = Env::start().await;
    let (roman, _alex) = env.ios_with_alex().await;
    let a = roman
        .ok("room_attach", json!({"room": "ios", "session": "W"}))
        .await;
    let b = roman
        .ok("room_attach", json!({"room": "ios", "session": "W"}))
        .await;
    assert_eq!(a["watch"]["url"], b["watch"]["url"]);
    let key: Vec<u8> = env
        .server
        .state
        .db
        .call(|c| {
            Ok(c.query_row(
                "SELECT key FROM server_keys WHERE name = 'watch'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("stored key");
    assert_eq!(key.len(), 32);
    assert_eq!(key, env.server.state.watch_key.to_vec());
}

/// The exact command handed to the agent, run through a real shell: curl
/// streams, grep drops keepalives and flushes each notice line at once.
#[tokio::test(flavor = "multi_thread")]
async fn monitor_command_prints_one_line_per_notice() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    let att = roman
        .ok("room_attach", json!({"room": "ios", "session": "W"}))
        .await;
    let cmd = att["watch"]["command"]
        .as_str()
        .expect("command")
        .to_string();
    // Own process group: the loop runs in a subshell, so killing sh alone
    // would leave it reconnecting and holding the test's stderr.
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sh");
    let pgid = child.id().expect("pid");
    let stdout = child.stdout.take().expect("stdout");
    let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stdout));
    tokio::time::sleep(Duration::from_millis(500)).await;
    alex.ok("room_send", json!({"room": "ios", "text": "hi"}))
        .await;
    let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .expect("a line arrives promptly")
        .expect("read")
        .expect("not EOF");
    assert!(
        line.starts_with("agentslam: new room items (1 in ios"),
        "{line}"
    );
    let _ = std::process::Command::new("kill")
        .args(["-TERM", "--", &format!("-{pgid}")])
        .status();
    child.kill().await.ok();
}

/// The reconnect loop stops on a clean close by the server: a session with
/// no attached room gets the reason line, the closing line, and the shell
/// exits (no endless reconnect).
#[tokio::test(flavor = "multi_thread")]
async fn monitor_command_stops_on_clean_close() {
    let env = Env::start().await;
    let (roman, _alex) = env.ios_with_alex().await;
    let att = roman
        .ok("room_attach", json!({"room": "ios", "session": "W"}))
        .await;
    let cmd = att["watch"]["command"]
        .as_str()
        .expect("command")
        .to_string();
    roman
        .ok("room_detach", json!({"room": "ios", "session": "W"}))
        .await;
    let out = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output(),
    )
    .await
    .expect("the loop ends on a clean close")
    .expect("run sh");
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "reason + closing line only: {text}");
    assert!(
        lines[0].starts_with("agentslam: no rooms attached to session W"),
        "{text}"
    );
    assert!(
        lines[1].starts_with("agentslam: watch stream closed."),
        "{text}"
    );
}
