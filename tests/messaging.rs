//! uc.agentslam.messaging — real-time exchange.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_broadcast_wait() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    let before = roman
        .ok("room_send", json!({"room": "ios", "text": "warm-up"}))
        .await["seq"]
        .as_i64()
        .expect("seq");
    let waiter = tokio::spawn(async move {
        let r = alex
            .ok(
                "room_wait",
                json!({"session": "alex-s1", "rooms": ["ios"], "timeout_s": 30}),
            )
            .await;
        (r, Instant::now())
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sent_at = Instant::now();
    roman
        .ok("room_send", json!({"room": "ios", "text": "ship it"}))
        .await;
    let (r, returned_at) = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("wait returned")
        .expect("task");
    let latency = returned_at.duration_since(sent_at);
    assert!(
        latency < Duration::from_secs(1),
        "room_wait latency {latency:?}"
    );
    let msgs = r["messages"].as_array().expect("messages");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["text"], json!("ship it"));
    assert_eq!(msgs[0]["from"], json!("roman/claude-pm"));
    assert_eq!(msgs[0]["seq"], json!(before + 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_wait_timeout() {
    let env = Env::start().await;
    let (_roman, alex) = env.ios_with_alex().await;
    let t0 = Instant::now();
    let r = alex
        .ok(
            "room_wait",
            json!({"session": "alex-s1", "rooms": ["ios"], "timeout_s": 2}),
        )
        .await;
    let took = t0.elapsed();
    assert_eq!(r["messages"], json!([]));
    assert_eq!(r["timed_out"], json!(true));
    assert!(
        took >= Duration::from_millis(1900) && took < Duration::from_millis(3500),
        "took {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_non_member_blocked() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    roman
        .ok("room_send", json!({"room": "ios", "text": "PRIVATE-1"}))
        .await;
    for (tool, args) in [
        ("room_read", json!({"room": "ios", "since": 0})),
        (
            "room_wait",
            json!({"session": "alex-s1", "rooms": ["ios"], "timeout_s": 1}),
        ),
        ("room_send", json!({"room": "ios", "text": "let me in"})),
        ("room_attach", json!({"room": "ios", "session": "alex-s1"})),
    ] {
        let r = alex.call(tool, args).await;
        assert_eq!(r["isError"], json!(true), "{tool}");
        assert_eq!(
            r["structuredContent"]["error"],
            json!("not_a_member"),
            "{tool}"
        );
        assert!(
            !r.to_string().contains("PRIVATE-1"),
            "{tool} leaked content"
        );
    }
    let count: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(count, 1, "non-member send stored nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_history_cap() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    let send_up_to = |n: i64| {
        let roman = &roman;
        async move {
            loop {
                let seq = roman
                    .ok("room_send", json!({"room": "ios", "text": "m"}))
                    .await["seq"]
                    .as_i64()
                    .expect("seq");
                if seq >= n {
                    break;
                }
            }
        }
    };
    send_up_to(10).await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    env.confirm_pending("roman", "ios", "alex/codex").await;
    send_up_to(15).await;
    env.remove("roman", "ios", "alex/codex").await;
    send_up_to(20).await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    env.confirm_pending("roman", "ios", "alex/codex").await;
    send_up_to(22).await;

    let read = alex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    let seqs: Vec<i64> = read["messages"]
        .as_array()
        .expect("m")
        .iter()
        .filter_map(|m| m["seq"].as_i64())
        .collect();
    assert_eq!(
        seqs,
        vec![21, 22],
        "only messages after the current admission"
    );
    let read = alex
        .ok("room_read", json!({"room": "ios", "since": 5}))
        .await;
    assert!(
        read["messages"]
            .as_array()
            .expect("m")
            .iter()
            .all(|m| m["seq"].as_i64() > Some(20))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_send_validation() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    assert_eq!(
        roman
            .err("room_send", json!({"room": "ios", "text": ""}))
            .await,
        "invalid_text"
    );
    let long = "x".repeat(16_001);
    assert_eq!(
        roman
            .err("room_send", json!({"room": "ios", "text": long}))
            .await,
        "invalid_text"
    );
    let count: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(count, 0, "nothing stored");
    // Boundary: exactly 16000 characters (multi-byte) is accepted.
    let max = "é".repeat(16_000);
    roman
        .ok("room_send", json!({"room": "ios", "text": max}))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_removal_immediate() {
    let env = Env::start().await;
    let (_roman, alex) = env.ios_with_alex().await;
    let alex = std::sync::Arc::new(alex);
    let a = alex.clone();
    let waiter = tokio::spawn(async move {
        let r = a
            .call(
                "room_wait",
                json!({"session": "alex-s1", "rooms": ["ios"], "timeout_s": 30}),
            )
            .await;
        (r, Instant::now())
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let removed_at = Instant::now();
    env.remove("roman", "ios", "alex/codex").await;
    let (r, returned_at) = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("wait ended")
        .expect("task");
    assert!(
        returned_at.duration_since(removed_at) < Duration::from_secs(1),
        "wait ended at once"
    );
    assert_eq!(r["isError"], json!(true));
    assert_eq!(r["structuredContent"]["error"], json!("not_a_member"));
    assert_eq!(
        alex.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );
    assert_eq!(
        alex.err("room_send", json!({"room": "ios", "text": "still here?"}))
            .await,
        "not_a_member"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_archived() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "before archive"}),
        )
        .await;
    let bob = env.agent("bob", "codex").await;
    let r = env
        .person("roman")
        .await
        .post_api("/api/rooms/ios/archive", None)
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        roman.room_status("ios").await.expect("ios")["state"],
        json!("archived")
    );
    assert_eq!(
        alex.err("room_send", json!({"room": "ios", "text": "x"}))
            .await,
        "room_archived"
    );
    assert_eq!(
        bob.err("room_request_join", json!({"room": "ios"})).await,
        "room_archived"
    );
    let read = alex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert!(
        read["messages"]
            .as_array()
            .expect("m")
            .iter()
            .any(|m| m["text"] == "before archive")
    );
}
