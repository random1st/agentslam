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

async fn agent_id(env: &Env, display: &str) -> i64 {
    let (handle, label) = display.split_once('/').expect("person/agent");
    let (h, l) = (handle.to_string(), label.to_string());
    env.server
        .state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT a.id FROM agents a JOIN persons p ON p.id = a.person_id WHERE p.handle = ?1 AND a.label = ?2",
                [h, l],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("agent id")
}

async fn send_n(agent: &Mcp, room: &str, n: usize, prefix: &str) {
    for i in 0..n {
        agent
            .ok(
                "room_send",
                json!({"room": room, "text": format!("{prefix} {i}")}),
            )
            .await;
    }
}

async fn open_requests(env: &Env) -> Vec<(i64, i64)> {
    env.server
        .state
        .db
        .call(|c| {
            let mut s = c.prepare(
                "SELECT seq, addressed_to FROM messages WHERE kind = 'summary_request' ORDER BY seq",
            )?;
            Ok(s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<(i64, i64)>>>()?)
        })
        .await
        .expect("requests")
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_summary_request() {
    let env = Env::start().await;
    let (claude, codex) = env.ios_with_alex().await; // roman/claude-pm, alex/codex
    let cursor = env.agent("bob", "cursor-1").await;
    cursor.ok("room_request_join", json!({"room": "ios"})).await;
    env.confirm_pending("roman", "ios", "bob/cursor-1").await;
    send_n(&claude, "ios", 20, "m").await;
    let online = [
        agent_id(&env, "roman/claude-pm").await,
        agent_id(&env, "alex/codex").await,
    ];
    let offline = agent_id(&env, "bob/cursor-1").await;
    let state = env.server.state.clone();

    for round in 0..6 {
        // cursor-1 goes stale (> 2 min); claude-pm and codex stay online.
        state.clock.advance(state.config.summary.request_ttl_s + 1);
        claude.ok("room_list", json!({})).await;
        codex.ok("room_list", json!({})).await;
        let posted = agentslam::rooms::summary::tick(&state).await.expect("tick");
        assert_eq!(posted, 1, "round {round}: one request");
        let again = agentslam::rooms::summary::tick(&state).await.expect("tick");
        assert_eq!(
            again, 0,
            "round {round}: no second request while one is open"
        );
        let reqs = open_requests(&env).await;
        assert_eq!(reqs.len(), round + 1);
        let (seq, to) = *reqs.last().expect("request");
        assert!(online.contains(&to), "addressed to an online member");
        assert_ne!(to, offline, "never to the offline member");

        // Only the addressee receives it, as kind summary_request.
        let (addressee, other) = if to == online[0] {
            (&claude, &codex)
        } else {
            (&codex, &claude)
        };
        let items = addressee
            .ok("room_read", json!({"room": "ios", "since": seq - 1}))
            .await;
        assert_eq!(items["messages"][0]["kind"], json!("summary_request"));
        assert_eq!(items["messages"][0]["from"], json!("agentslam"));
        let seen = other
            .ok("room_read", json!({"room": "ios", "since": seq - 1}))
            .await;
        assert_eq!(seen["messages"], json!([]), "not shown to others");
    }

    // A posted summary closes the cycle: no request until 20 new messages.
    claude
        .ok(
            "room_summarize",
            json!({"room": "ios", "text": "- shipped the build"}),
        )
        .await;
    state.clock.advance(state.config.summary.request_ttl_s + 1);
    claude.ok("room_list", json!({})).await;
    assert_eq!(
        agentslam::rooms::summary::tick(&state).await.expect("tick"),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_request_policy() {
    let env = Env::start().await;
    let (roman, _alex) = env.ios_with_alex().await;
    let markers = ["reveals no secret", "explicit approval", "informational"];
    let init = roman.initialize().await;
    let instructions = init["instructions"].as_str().unwrap_or_default();
    for m in markers {
        assert!(instructions.contains(m), "instructions: {m}");
    }
    let (status, tools) = roman.rpc_raw("tools/list", json!({})).await;
    assert_eq!(status, 200);
    for name in ["room_read", "room_wait", "room_summarize"] {
        let t = tools["result"]["tools"]
            .as_array()
            .and_then(|a| a.iter().find(|t| t["name"] == name))
            .cloned()
            .expect("tool listed");
        let d = t["description"].as_str().unwrap_or_default();
        for m in markers {
            assert!(d.contains(m), "{name} description: {m}");
        }
    }
    roman
        .ok("room_send", json!({"room": "ios", "text": "hi"}))
        .await;
    let read = roman
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    let wait = roman
        .ok(
            "room_wait",
            json!({"session": "S", "rooms": ["ios"], "timeout_s": 1}),
        )
        .await;
    for (what, v) in [("room_read", &read), ("room_wait", &wait)] {
        let p = v["policy"].as_str().unwrap_or_default();
        for m in markers {
            assert!(p.contains(m), "{what} policy: {m}");
        }
    }
    assert_eq!(read["messages"][0]["kind"], json!("message"));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_messaging_join_summary() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let codex = env.agent("roman", "codex").await;
    roman.ok("room_create", json!({"name": "ios"})).await;
    send_n(&roman, "ios", 20, "early").await;
    let s = roman
        .ok(
            "room_summarize",
            json!({"room": "ios", "text": "- decided: ship 1.2\n- open: crash on launch"}),
        )
        .await;
    assert_eq!(s["seq"], json!(21));
    assert_eq!(s["kind"], json!("summary"));
    send_n(&roman, "ios", 4, "late").await; // 22..25
    codex.ok("room_request_join", json!({"room": "ios"})).await;
    env.confirm_pending("roman", "ios", "roman/codex").await;

    let read = codex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    let items = read["messages"].as_array().expect("items");
    assert_eq!(items.len(), 1, "only the summary: {items:?}");
    assert_eq!(items[0]["kind"], json!("summary"));
    assert_eq!(items[0]["seq"], json!(21));
    assert_eq!(items[0]["from"], json!("roman/claude-pm"));
    assert!(
        items[0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("ship 1.2")
    );

    roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "after admission"}),
        )
        .await;
    let read = codex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    let seqs: Vec<i64> = read["messages"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|m| m["seq"].as_i64())
        .collect();
    assert_eq!(
        seqs,
        vec![21, 26],
        "summary first, then post-admission only"
    );
    for item in read["messages"].as_array().expect("items") {
        assert!(item.get("kind").is_some(), "every item carries kind");
    }

    // A session attaching now gets the summary first through room_wait too.
    codex
        .ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;
    let w = codex
        .ok("room_wait", json!({"session": "S", "timeout_s": 2}))
        .await;
    let kinds: Vec<&str> = w["messages"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|m| m["kind"].as_str())
        .collect();
    assert_eq!(kinds, vec!["summary", "message"]);
}
