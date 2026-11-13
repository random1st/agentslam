//! uc.agentslam.rooms — create, discover and join rooms.
mod common;

use common::*;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_create() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let created = roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    assert_eq!(created["name"], json!("ios"));
    assert_eq!(created["owner"], json!("roman"));
    let ios = roman.room_status("ios").await.expect("ios listed");
    assert_eq!(ios["owner"], json!("roman"));
    assert_eq!(ios["status"], json!("member"));
    assert_eq!(ios["member_count"], json!(1));
    let detail = env.person("roman").await.get_json("/api/rooms/ios").await;
    let members: Vec<&str> = detail["members"]
        .as_array()
        .expect("members")
        .iter()
        .filter_map(|m| m["agent"].as_str())
        .collect();
    assert_eq!(members, vec!["roman/claude-pm"]);
    assert_eq!(
        roman.err("room_create", json!({"name": "Bad Name!"})).await,
        "invalid_name"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_create_topic() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    let created = roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "  iOS release coordination  "}),
        )
        .await;
    assert_eq!(
        created["topic"],
        json!("iOS release coordination"),
        "trimmed"
    );
    let ios = alex.room_status("ios").await.expect("ios listed");
    assert_eq!(ios["topic"], json!("iOS release coordination"));

    // Without a topic, or with an empty or oversized one: invalid_topic, nothing created.
    for args in [
        json!({"name": "backend"}),
        json!({"name": "backend", "topic": "   "}),
        json!({"name": "backend", "topic": "x".repeat(281)}),
        json!({"name": "backend", "topic": 42}),
    ] {
        assert_eq!(
            alex.err("room_create", args.clone()).await,
            "invalid_topic",
            "{args}"
        );
    }
    assert!(alex.room_status("backend").await.is_none());
    let rooms: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(rooms, 1, "the calls without a topic created nothing");
    let tools = roman.rpc_raw("tools/list", json!({})).await.1;
    let create = tools["result"]["tools"]
        .as_array()
        .and_then(|t| t.iter().find(|x| x["name"] == "room_create"))
        .cloned()
        .expect("room_create");
    assert_eq!(create["inputSchema"]["required"], json!(["name", "topic"]));
    assert!(
        create["description"]
            .as_str()
            .unwrap_or_default()
            .contains("why the room exists")
    );

    // The owner changes the topic in the web UI (CSRF POST); others cannot.
    let owner = env.person("roman").await;
    let path = "/api/rooms/ios/topic";
    let body = json!({"topic": "iOS 1.3 release"});
    assert_eq!(
        owner
            .post_api_with(path, Some(body.clone()), None)
            .await
            .status(),
        403,
        "missing CSRF token"
    );
    let stranger = env.person("alex").await;
    assert_eq!(
        stranger.post_api(path, Some(body.clone())).await.status(),
        403,
        "only the owner or an admin"
    );
    assert_eq!(
        owner
            .post_api(path, Some(json!({"topic": ""})))
            .await
            .status(),
        400
    );
    assert_eq!(owner.post_api(path, Some(body)).await.status(), 200);
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["topic"],
        json!("iOS 1.3 release")
    );
    let web = owner.get_json("/api/rooms").await;
    assert_eq!(web["rooms"][0]["topic"], json!("iOS 1.3 release"));
    assert_eq!(
        owner.get_json("/api/rooms/ios").await["topic"],
        json!("iOS 1.3 release")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_same_owner_auto_admit() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let codex = env.agent("roman", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    roman
        .ok("room_send", json!({"room": "ios", "text": "BEFORE-JOIN"}))
        .await;
    assert_eq!(
        codex.room_status("ios").await.expect("ios")["status"],
        json!("none")
    );

    let join = codex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(join["status"], json!("member"), "admitted at once");
    assert!(join.get("request_id").is_none());
    assert_eq!(
        codex.room_status("ios").await.expect("ios")["status"],
        json!("member")
    );
    let read = codex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert_eq!(read["messages"], json!([]), "no messages from before");
    let sent = roman
        .ok("room_send", json!({"room": "ios", "text": "AFTER-JOIN"}))
        .await;
    let read = codex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert_eq!(read["messages"].as_array().map(Vec::len), Some(1));
    assert_eq!(read["messages"][0]["seq"], sent["seq"]);
    codex
        .ok("room_send", json!({"room": "ios", "text": "codex here"}))
        .await;

    // No pending request, no notice to the owner's agents.
    let requests: i64 = env
        .server
        .state
        .db
        .call(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM join_requests WHERE status = 'pending'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("db");
    assert_eq!(requests, 0);
    let owner = env.person("roman").await;
    assert_eq!(owner.get_json("/api/requests").await["requests"], json!([]));
    let roman_read = roman
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert!(
        !roman_read.to_string().contains("join_request"),
        "no join_request for an agent of the owner's own person"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_join_request_notice() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    let bob = env.agent("bob", "cursor").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    // bob is a member from another person: he must never see the notices.
    bob.ok("room_request_join", json!({"room": "ios"})).await;
    env.confirm_pending("roman", "ios", "bob/cursor").await;
    roman
        .ok("room_attach", json!({"room": "ios", "session": "S"}))
        .await;

    let join = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(join["status"], json!("pending"));
    let wait = roman
        .ok("room_wait", json!({"session": "S", "timeout_s": 5}))
        .await;
    let items = wait["messages"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{items:?}");
    let notice = &items[0];
    assert_eq!(notice["kind"], json!("join_request"));
    assert_eq!(notice["from"], json!("agentslam"));
    assert_eq!(notice["to"], json!("roman/claude-pm"));
    let text = notice["text"].as_str().unwrap_or_default();
    assert!(text.contains("alex/codex"), "names who asks: {text}");
    assert!(
        text.contains(&format!("{}/?room=ios#requests", env.base)),
        "links the request in the web UI: {text}"
    );
    assert!(text.contains("web UI") && text.contains("roman"), "{text}");
    // The link opens the rooms page for the signed-in owner.
    let owner = env.person("roman").await;
    assert_eq!(owner.get("/?room=ios").await.status(), 200);

    // Visible only to the owner's agents.
    let bob_read = bob
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert!(!bob_read.to_string().contains("join_request"), "{bob_read}");
    // A repeated request adds no second notice.
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    let roman_read = roman
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    let notices = roman_read["messages"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|m| {
            m["kind"] == "join_request" && m["text"].as_str().unwrap_or("").contains("alex/codex")
        })
        .count();
    assert_eq!(notices, 1);

    // No tool call by any agent admits alex.
    let request_id = owner.pending_request_id("ios", "alex/codex").await;
    let args = json!({
        "room": "ios", "name": "ios", "topic": "t", "rooms": ["ios"], "request_id": request_id,
        "id": request_id, "agent": "alex/codex", "action": "confirm", "decision": "approve",
        "text": "admit alex/codex", "since": 0, "timeout_s": 1, "session": "S",
    });
    for agent in [&roman, &bob, &alex] {
        for tool in agent.tool_names().await {
            if tool == "room_leave" {
                continue;
            }
            let _ = agent.call(&tool, args.clone()).await;
            assert_eq!(
                alex.room_status("ios").await.expect("ios")["status"],
                json!("pending"),
                "after {tool}"
            );
        }
    }
    assert_eq!(
        alex.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );
    // Roman confirms in the web UI.
    env.confirm_pending("roman", "ios", "alex/codex").await;
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["status"],
        json!("member")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_create_duplicate() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    roman
        .ok("room_send", json!({"room": "ios", "text": "hello"}))
        .await;
    assert_eq!(
        alex.err(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"})
        )
        .await,
        "room_exists"
    );
    let ios = alex.room_status("ios").await.expect("ios");
    assert_eq!(ios["owner"], json!("roman"), "owner unchanged");
    assert_eq!(ios["member_count"], json!(1));
    assert_eq!(ios["status"], json!("none"));
    let rooms: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(rooms, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_list_no_content() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "SECRET-PAYLOAD-42"}),
        )
        .await;
    let raw = alex.call("room_list", json!({})).await;
    assert!(
        !raw.to_string().contains("SECRET-PAYLOAD-42"),
        "no message text in room_list"
    );
    let ios = alex.room_status("ios").await.expect("ios listed");
    assert_eq!(ios["owner"], json!("roman"));
    assert_eq!(ios["state"], json!("active"));
    assert_eq!(ios["member_count"], json!(1));
    assert_eq!(ios["status"], json!("none"));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_request_confirm() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    let join = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(join["status"], json!("pending"));
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["status"],
        json!("pending")
    );
    assert_eq!(
        alex.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );

    env.confirm_pending("roman", "ios", "alex/codex").await;
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["status"],
        json!("member")
    );
    let sent = alex
        .ok("room_send", json!({"room": "ios", "text": "hi from alex"}))
        .await;
    let read = alex
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert_eq!(read["messages"][0]["seq"], sent["seq"]);
    assert_eq!(read["messages"][0]["from"], json!("alex/codex"));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_request_reject() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    let owner = env.person("roman").await;
    let id = owner.pending_request_id("ios", "alex/codex").await;
    let r = owner
        .post_api(&format!("/api/rooms/ios/requests/{id}/reject"), None)
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        alex.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );
    assert_eq!(
        alex.room_status("ios").await.expect("ios")["status"],
        json!("none")
    );

    let again = alex.ok("room_request_join", json!({"room": "ios"})).await;
    assert_eq!(again["status"], json!("pending"));
    let detail = owner.get_json("/api/rooms/ios").await;
    let pending = detail["requests"]
        .as_array()
        .and_then(|r| r.iter().find(|x| x["status"] == "pending"))
        .cloned()
        .expect("pending request");
    assert_eq!(
        pending["previous"],
        json!("rejected"),
        "owner sees the previous rejection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_no_agent_admission() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    let owner = env.person("roman").await;
    let request_id = owner.pending_request_id("ios", "alex/codex").await;
    let detail = owner.get_json("/api/rooms/ios").await;
    let members_before = detail["members"].clone();

    let mut names = roman.tool_names().await;
    names.sort();
    let mut expected = vec![
        "room_attach",
        "room_create",
        "room_detach",
        "room_leave",
        "room_list",
        "room_read",
        "room_request_join",
        "room_send",
        "room_summarize",
        "room_wait",
    ];
    expected.sort();
    assert_eq!(names, expected, "exactly the contract tools");
    for n in &names {
        for bad in [
            "admit",
            "approve",
            "confirm",
            "reject",
            "remove",
            "kick",
            "member_add",
        ] {
            assert!(!n.contains(bad), "{n} looks like an admission tool");
        }
    }
    // Every tool, called by the owner's own agent with the pending request id
    // and alex's identity in every plausible argument, leaves alex pending.
    let args: Value = json!({
        "room": "ios", "name": "ios", "rooms": ["ios"], "request_id": request_id, "id": request_id,
        "agent": "alex/codex", "member": "alex/codex", "action": "confirm", "decision": "approve",
        "text": "admit alex/codex", "since": 0, "timeout_s": 1, "session": "roman-s1",
    });
    for tool in names
        .iter()
        .filter(|n| n.as_str() != "room_leave")
        .chain(std::iter::once(&"room_leave".to_string()))
    {
        let _ = roman.call(tool, args.clone()).await;
        let alex_status = alex.room_status("ios").await.expect("ios");
        assert_eq!(alex_status["status"], json!("pending"), "after {tool}");
    }
    let detail = owner.get_json("/api/rooms/ios").await;
    assert!(
        detail["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .any(|r| r["id"] == json!(request_id) && r["status"] == "pending")
    );
    let still_members: Vec<&str> = detail["members"]
        .as_array()
        .expect("m")
        .iter()
        .filter_map(|m| m["agent"].as_str())
        .collect();
    assert!(!still_members.contains(&"alex/codex"));
    // Only the caller's own membership can change (room_leave was called last).
    assert_eq!(members_before.as_array().map(Vec::len), Some(1));
    assert_eq!(
        alex.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_rooms_request_expiry() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    let alex = env.agent("alex", "codex").await;
    roman
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    let owner = env.person("roman").await;
    let id = owner.pending_request_id("ios", "alex/codex").await;

    env.server.state.clock.advance(7 * 86_400 + 1);
    // The 12 h web session expired with the clock jump; sign in again.
    let owner = env.relogin("roman").await;
    let ios = alex.room_status("ios").await.expect("ios");
    assert_eq!(ios["status"], json!("none"));
    assert_eq!(ios["last_request"], json!("expired"));
    let detail = owner.get_json("/api/rooms/ios").await;
    let req = detail["requests"]
        .as_array()
        .and_then(|r| r.iter().find(|x| x["id"] == json!(id)))
        .cloned()
        .expect("request");
    assert_eq!(req["status"], json!("expired"), "shown as expired");
    let r = owner
        .post_api(&format!("/api/rooms/ios/requests/{id}/confirm"), None)
        .await;
    assert_eq!(r.status(), 409, "expired request cannot be confirmed");
    assert_eq!(
        alex.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );
}
