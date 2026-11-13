//! uc.agentslam.sessions — session room sets (explicit `session` argument) and hooks.
mod common;

use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

fn attached_rooms(list: &Value) -> Vec<String> {
    let mut v: Vec<String> = list["rooms"]
        .as_array()
        .expect("rooms")
        .iter()
        .filter(|r| r["attached"] == json!(true))
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .collect();
    v.sort();
    v
}

fn seqs(wait: &Value) -> Vec<i64> {
    wait["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .filter_map(|m| m["seq"].as_i64())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_sessions_restore() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    roman
        .ok(
            "room_create",
            json!({"name": "backend", "topic": "Backend API work"}),
        )
        .await;
    roman
        .ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;
    roman
        .ok("room_attach", json!({"room": "backend", "session": "S"}))
        .await;
    for i in 1..=5 {
        roman
            .ok("room_send", json!({"room": "ios", "text": format!("m{i}")}))
            .await;
    }
    // Session S reads up to seq 5.
    let w = roman
        .ok("room_wait", json!({"session": "S", "timeout_s": 5}))
        .await;
    assert_eq!(seqs(&w), vec![1, 2, 3, 4, 5]);

    // Reconnect: a brand-new client with the same token, calling with session S.
    let again = roman.reconnect();
    again.initialize().await;
    let list = again.ok("room_list", json!({"session": "S"})).await;
    assert_eq!(attached_rooms(&list), vec!["backend", "ios"]);
    roman
        .ok("room_send", json!({"room": "ios", "text": "m6"}))
        .await;
    let w = again
        .ok("room_wait", json!({"session": "S", "timeout_s": 5}))
        .await;
    assert_eq!(seqs(&w), vec![6], "the next room_wait starts after seq 5");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_sessions_new_session_empty() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    roman
        .ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;
    let t0 = Instant::now();
    let w = roman
        .ok("room_wait", json!({"session": "T", "timeout_s": 10}))
        .await;
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "returns at once, no waiting on nothing"
    );
    assert_eq!(w["rooms_attached"], json!(false));
    assert_eq!(w["messages"], json!([]));
    assert!(
        w["note"]
            .as_str()
            .unwrap_or_default()
            .contains("no rooms attached")
    );
    let list_t = roman.ok("room_list", json!({"session": "T"})).await;
    assert!(attached_rooms(&list_t).is_empty());
    let list_s = roman.ok("room_list", json!({"session": "S"})).await;
    assert_eq!(attached_rooms(&list_s), vec!["ios"], "S keeps its set");
    let list_none = roman.ok("room_list", json!({})).await;
    assert!(
        attached_rooms(&list_none).is_empty(),
        "no session, nothing marked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_sessions_concurrent_isolated() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    roman
        .ok(
            "room_create",
            json!({"name": "backend", "topic": "Backend API work"}),
        )
        .await;
    // Two clients, same token, open at the same time.
    let s = roman.reconnect();
    let t = roman.reconnect();
    s.ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;
    t.ok("room_attach", json!({"room": "backend", "session": "T"}))
        .await;

    let wait_s = tokio::spawn(async move {
        s.ok("room_wait", json!({"session": "S", "timeout_s": 10}))
            .await
    });
    let wait_t = tokio::spawn(async move {
        t.ok("room_wait", json!({"session": "T", "timeout_s": 2}))
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    roman
        .ok("room_send", json!({"room": "ios", "text": "for S only"}))
        .await;

    let ws = tokio::time::timeout(Duration::from_secs(5), wait_s)
        .await
        .expect("S returned")
        .expect("task");
    assert_eq!(ws["messages"][0]["text"], json!("for S only"));
    assert_eq!(ws["messages"][0]["room"], json!("ios"));
    let wt = tokio::time::timeout(Duration::from_secs(5), wait_t)
        .await
        .expect("T returned")
        .expect("task");
    assert_eq!(wt["messages"], json!([]), "T does not get the ios message");
    assert_eq!(wt["timed_out"], json!(true));

    let list_s = roman.ok("room_list", json!({"session": "S"})).await;
    let list_t = roman.ok("room_list", json!({"session": "T"})).await;
    assert_eq!(attached_rooms(&list_s), vec!["ios"]);
    assert_eq!(attached_rooms(&list_t), vec!["backend"]);
}

/// Not an acceptance criterion: the `session` argument contract and the
/// removed header path.
#[tokio::test(flavor = "multi_thread")]
async fn session_argument_is_required_and_validated() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    let long = "a".repeat(129);
    for bad in [
        json!(null),
        json!(""),
        json!("has space"),
        json!("ü"),
        json!(long),
        json!(7),
    ] {
        let mut args = json!({"room": "ios", "timeout_s": 1});
        if !bad.is_null() {
            args["session"] = bad.clone();
        }
        assert_eq!(
            roman.err("room_wait", args.clone()).await,
            "invalid_session",
            "{bad}"
        );
        assert_eq!(
            roman.err("room_attach", args.clone()).await,
            "invalid_session",
            "{bad}"
        );
        assert_eq!(
            roman.err("room_detach", args.clone()).await,
            "invalid_session",
            "{bad}"
        );
        if !bad.is_null() {
            assert_eq!(
                roman.err("room_list", args).await,
                "invalid_session",
                "{bad}"
            );
        }
    }
    let max = "A-z0.9_:".repeat(16);
    assert_eq!(max.len(), 128);
    roman
        .ok("room_attach", json!({"room": "ios", "session": max}))
        .await;

    // The old header is ignored: without a `session` argument the call fails.
    let resp = reqwest::Client::new()
        .post(format!("{}/mcp", env.base))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .header("x-agentslam-session", "S")
        .bearer_auth(&roman.token)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "room_wait", "arguments": {"timeout_s": 1}}}))
        .send()
        .await
        .expect("request");
    let body: Value = resp.json().await.expect("json");
    assert_eq!(
        body["result"]["structuredContent"]["error"],
        json!("invalid_session")
    );
}

/// Run the real binary: `agentslam hook <kind>` with hook JSON on stdin.
async fn run_hook(kind: &str, url: &str, token: &str, stdin_json: &str) -> (i32, String, Duration) {
    let t0 = Instant::now();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentslam"))
        .arg("hook")
        .arg(kind)
        .env("AGENTSLAM_URL", url)
        .env("AGENTSLAM_TOKEN", token)
        .env("AGENTSLAM_HOOK_CONFIG", "/nonexistent/agentslam-hook.toml")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin
        .write_all(stdin_json.as_bytes())
        .await
        .expect("write stdin");
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("hook finished")
        .expect("output");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        t0.elapsed(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_sessions_hook_prompt() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    roman
        .ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;
    alex.ok(
        "room_send",
        json!({"room": "ios", "text": "first <b>note</b>"}),
    )
    .await;
    alex.ok("room_send", json!({"room": "ios", "text": "second note"}))
        .await;

    let stdin = r#"{"session_id":"S","hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;
    let (code, out, _) = run_hook("prompt", &env.base, &roman.token, stdin).await;
    assert_eq!(code, 0);
    assert_eq!(out.matches("<room-message ").count(), 2, "{out}");
    assert!(
        out.contains("<room-message room=\"ios\" from=\"alex/codex\" seq=\""),
        "{out}"
    );
    assert!(out.contains("untrusted>"), "{out}");
    assert!(
        out.contains("first &lt;b&gt;note&lt;/b&gt;") && out.contains("second note"),
        "{out}"
    );

    let (code, out, _) = run_hook("prompt", &env.base, &roman.token, stdin).await;
    assert_eq!(code, 0);
    assert_eq!(out, "", "second run prints nothing: cursors advanced");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_sessions_hook_session_start() {
    // No server needed: the hook only reflects the host session id.
    let stdin =
        r#"{"session_id":"3f2a-S.1:x","hook_event_name":"SessionStart","source":"startup"}"#;
    let (code, out, took) = run_hook("session-start", "http://127.0.0.1:9", "unused", stdin).await;
    assert_eq!(code, 0);
    assert!(out.contains("agentslam session: 3f2a-S.1:x"), "{out}");
    assert!(out.contains("session=\"3f2a-S.1:x\""), "{out}");
    for tool in ["room_attach", "room_detach", "room_wait", "room_list"] {
        assert!(out.contains(tool), "mentions {tool}: {out}");
    }
    assert!(took < Duration::from_secs(5));

    // Resume/compaction passes the same id: same output.
    let resume =
        r#"{"session_id":"3f2a-S.1:x","hook_event_name":"SessionStart","source":"resume"}"#;
    let (_, out2, _) = run_hook("session-start", "http://127.0.0.1:9", "unused", resume).await;
    assert_eq!(out2, out);

    // An id outside the session alphabet: nothing printed, still exit 0.
    let bad = r#"{"session_id":"has space","hook_event_name":"SessionStart"}"#;
    let (code, out, _) = run_hook("session-start", "http://127.0.0.1:9", "unused", bad).await;
    assert_eq!(code, 0);
    assert_eq!(out, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_sessions_hook_stop_nonblocking() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    roman
        .ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;
    alex.ok("room_send", json!({"room": "ios", "text": "a"}))
        .await;
    alex.ok("room_send", json!({"room": "ios", "text": "b"}))
        .await;
    let stdin = r#"{"session_id":"S","hook_event_name":"Stop","stop_hook_active":false}"#;

    let (code, out, took) = run_hook("stop", &env.base, &roman.token, stdin).await;
    assert_eq!(code, 0);
    assert!(out.contains("2 unread") && out.contains("ios: 2"), "{out}");
    assert!(
        !out.contains("decision") && !out.contains("block"),
        "never a block decision: {out}"
    );
    assert!(took < Duration::from_secs(5));
    // Count only: the stop hook does not consume messages.
    let (_, out2, _) = run_hook("stop", &env.base, &roman.token, stdin).await;
    assert!(out2.contains("2 unread"));

    // Server unreachable: still exits 0 with nothing on stdout, quickly.
    let (code, out, took) = run_hook("stop", "http://127.0.0.1:9", &roman.token, stdin).await;
    assert_eq!(code, 0);
    assert_eq!(out, "");
    assert!(took < Duration::from_secs(5), "took {took:?}");
}
