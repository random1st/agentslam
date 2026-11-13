//! uc.agentslam.web — watch and govern rooms in the web UI.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

/// Read SSE chunks until `needle` appears or the deadline passes.
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
async fn s5d_ac_uc_agentslam_web_live_stream() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    let bob = env.agent("bob", "codex").await;
    bob.ok("room_request_join", json!({"room": "ios"})).await;
    let owner = env.person("roman").await;

    // The page loads: index HTML for a signed-in person, then room detail.
    let index = owner.get("/").await;
    assert_eq!(index.status(), 200);
    assert!(index.text().await.expect("html").contains("/static/app.js"));
    let detail = owner.get_json("/api/rooms/ios").await;
    let members = detail["members"].as_array().expect("members");
    assert!(
        members
            .iter()
            .any(|m| m["agent"] == "roman/claude-pm" && m["presence"] == "online")
    );
    assert!(
        members
            .iter()
            .any(|m| m["agent"] == "alex/codex" && m["presence"] == "online")
    );
    assert!(
        detail["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .any(|r| r["agent"] == "bob/codex" && r["status"] == "pending")
    );

    let mut stream = owner.get("/api/rooms/ios/events").await;
    assert_eq!(stream.status(), 200);
    assert!(
        read_until(&mut stream, "event: ready", Duration::from_secs(2))
            .await
            .is_some()
    );
    let sent_at = Instant::now();
    alex.ok(
        "room_send",
        json!({"room": "ios", "text": "live from alex"}),
    )
    .await;
    let got = read_until(&mut stream, "live from alex", Duration::from_secs(3))
        .await
        .expect("message on the stream");
    assert!(
        sent_at.elapsed() < Duration::from_secs(1),
        "SSE delivery took {:?}",
        sent_at.elapsed()
    );
    assert!(got.contains("event: message") && got.contains("alex/codex"));
    let _ = roman;
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_web_web_scope() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    roman
        .ok("room_send", json!({"room": "ios", "text": "ROMAN-ONLY"}))
        .await;
    let alex = env.person("alex").await;
    // Alex even has an agent with a pending request — still not a member.
    let alex_agent = env.agent("alex", "codex").await;
    alex_agent
        .ok("room_request_join", json!({"room": "ios"}))
        .await;

    let rooms = alex.get_json("/api/rooms").await;
    assert_eq!(rooms["rooms"], json!([]));
    let detail = alex.get("/api/rooms/ios").await;
    assert_eq!(detail.status(), 403);
    assert!(!detail.text().await.expect("body").contains("ROMAN-ONLY"));
    let stream = alex.get("/api/rooms/ios/events").await;
    assert_eq!(stream.status(), 403, "stream request refused");
    let r = alex.post_api("/api/rooms/ios/archive", None).await;
    assert_eq!(r.status(), 403, "no owner actions either");
    // Signed out: nothing at all.
    assert_eq!(env.browser().get("/api/rooms/ios").await.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_web_csrf() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    let owner = env.person("roman").await;
    let id = owner.pending_request_id("ios", "alex/codex").await;
    let path = format!("/api/rooms/ios/requests/{id}/confirm");

    let r = owner.post_api_with(&path, None, None).await;
    assert_eq!(r.status(), 403, "missing CSRF token");
    let r = owner.post_api_with(&path, None, Some("forged-token")).await;
    assert_eq!(r.status(), 403, "wrong CSRF token");
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["status"],
        json!("pending"),
        "membership unchanged"
    );
    for p in [
        "/api/rooms/ios/archive",
        "/api/rooms/ios/delete",
        "/api/agent-tokens",
    ] {
        assert_eq!(
            owner
                .post_api_with(p, Some(json!({"label": "x1"})), None)
                .await
                .status(),
            403,
            "{p}"
        );
    }
    assert_eq!(
        roman.room_status("ios").await.expect("ios")["state"],
        json!("active")
    );

    let r = owner.post_api(&path, None).await;
    assert_eq!(r.status(), 200, "valid token works");
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["status"],
        json!("member")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_web_delete_room() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "TRANSCRIPT-LINE"}),
        )
        .await;
    alex.ok("room_send", json!({"room": "ios", "text": "another"}))
        .await;
    let owner = env.person("roman").await;
    let r = owner.post_api("/api/rooms/ios/delete", None).await;
    assert_eq!(r.status(), 200);

    assert!(
        roman.room_status("ios").await.is_none(),
        "gone from room_list"
    );
    assert!(alex.room_status("ios").await.is_none());
    let messages: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(messages, 0, "transcript purged");
    let values = env.all_text_values().await;
    assert!(!values.iter().any(|v| v.contains("TRANSCRIPT-LINE")));
    assert_eq!(
        roman
            .err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "room_not_found"
    );
    // The name is free again.
    roman.ok("room_create", json!({"name": "ios"})).await;
}

/// Not an acceptance criterion (B11 UX): pending requests lead the page and are
/// listed across rooms; the page explains how to connect an agent; no jargon.
#[tokio::test(flavor = "multi_thread")]
async fn rooms_page_ux_contract() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    roman.ok("room_create", json!({"name": "backend"})).await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    alex.ok("room_request_join", json!({"room": "backend"}))
        .await;
    let owner = env.person("roman").await;

    let html = owner.get("/").await.text().await.expect("index");
    let requests_at = html
        .find("Waiting for your answer")
        .expect("requests section");
    let rooms_at = html.find("Your rooms</h2>").expect("rooms section");
    assert!(requests_at < rooms_at, "pending requests come first");
    assert!(html.contains("Connect an agent"));
    assert!(
        html.contains("<dialog"),
        "destructive actions confirm in a dialog"
    );
    let lower = html.to_lowercase();
    for jargon in ["handle", "cimd", "seq", "admission"] {
        assert!(!lower.contains(jargon), "jargon on screen: {jargon}");
    }
    let css = owner
        .get("/static/style.css")
        .await
        .text()
        .await
        .expect("css");
    assert!(css.contains("prefers-color-scheme: dark"));
    assert!(css.contains(":focus-visible"));

    let me = owner.get_json("/api/me").await;
    assert_eq!(me["mcp_url"], json!(format!("{}/mcp", env.base)));
    let pending = owner.get_json("/api/requests").await;
    let rooms: Vec<&str> = pending["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .filter_map(|r| r["room"].as_str())
        .collect();
    assert_eq!(
        rooms,
        vec!["ios", "backend"],
        "all owned rooms, oldest first"
    );
    // Alex owns nothing: nothing to answer, and no access to roman's requests.
    let alex_browser = env.person("alex").await;
    assert_eq!(
        alex_browser.get_json("/api/requests").await["requests"],
        json!([])
    );
    // Unknown pages are a plain 404, not a sign-in challenge.
    assert_eq!(owner.get("/nope").await.status(), 404);
}
