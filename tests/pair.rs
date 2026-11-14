//! Pair vibecoding over MCP only (B6b) and same-organization invite links (B5a).
mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

fn texts(items: &Value) -> Vec<String> {
    items
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["text"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Roman creates an invite for `room`; returns the link and its id.
async fn invite(env: &Env, owner: &str, room: &str) -> (String, i64) {
    let b = env.person(owner).await;
    let r = b
        .post_api(&format!("/api/rooms/{room}/invites"), Some(json!({})))
        .await;
    assert_eq!(r.status(), 201, "create invite");
    let v: Value = r.json().await.expect("json");
    let link = v["link"].as_str().expect("link").to_string();
    assert!(link.contains("/?invite=asi_"), "{link}");
    (link, v["invite"]["id"].as_i64().expect("id"))
}

/// The browser opens the link (the server keeps the token in a cookie) and
/// presses Join; returns the status of the Join call.
async fn open_and_join(b: &Browser, link: &str) -> u16 {
    let r = b.get(link).await;
    assert_eq!(r.status(), 303, "invite link redirects");
    assert_eq!(
        location(&r),
        "/",
        "a signed-in person lands on the rooms page"
    );
    b.post_api("/api/invite/accept", None)
        .await
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_send_returns_unread() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    // Roman's session attaches through its first send.
    let first = roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "starting on the paywall", "session": "s1"}),
        )
        .await;
    assert_eq!(first["unread"], json!([]), "nothing new yet: {first}");
    assert!(
        first["policy"].is_string(),
        "the request policy rides along"
    );

    alex.ok(
        "room_send",
        json!({"room": "ios", "text": "I take the API"}),
    )
    .await;
    alex.ok(
        "room_send",
        json!({"room": "ios", "text": "tests are red on main"}),
    )
    .await;

    let r = roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "paywall done", "session": "s1"}),
        )
        .await;
    assert_eq!(r["text"], json!("paywall done"), "the stored message: {r}");
    assert_eq!(
        texts(&r["unread"]),
        vec!["I take the API", "tests are red on main"],
        "partner messages arrive with the send"
    );
    assert_eq!(r["untrusted"], json!(true));

    let again = roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "next: store copy", "session": "s1"}),
        )
        .await;
    assert_eq!(again["unread"], json!([]), "already delivered: {again}");

    // Without a session the result is the stored message only, as before.
    let plain = alex
        .ok("room_send", json!({"room": "ios", "text": "ok"}))
        .await;
    assert!(plain.get("unread").is_none(), "{plain}");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_send_wait_reply() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    let answer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        alex.ok(
            "room_send",
            json!({"room": "ios", "text": "use the v2 endpoint"}),
        )
        .await;
    });
    let r = roman
        .ok(
            "room_send",
            json!({"room": "ios", "text": "which endpoint?", "session": "s1", "wait_reply_s": 10}),
        )
        .await;
    answer.await.expect("partner task");
    assert_eq!(texts(&r["reply"]), vec!["use the v2 endpoint"], "{r}");
    assert_eq!(r["reply_timed_out"], json!(false));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_wait_reply_needs_session() {
    let env = Env::start().await;
    let (roman, alex) = env.ios_with_alex().await;
    let code = roman
        .err(
            "room_send",
            json!({"room": "ios", "text": "lost?", "wait_reply_s": 5}),
        )
        .await;
    assert_eq!(code, "bad_request");
    let read = alex.ok("room_read", json!({"room": "ios"})).await;
    assert!(
        !texts(&read["messages"]).contains(&"lost?".to_string()),
        "nothing was stored"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_invite_join() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude").await;
    roman
        .ok(
            "room_create",
            json!({"name": "pair", "topic": "Pair on the checkout"}),
        )
        .await;
    let (link, _) = invite(&env, "roman", "pair").await;

    let bob = env.agent("bob", "codex").await;
    let bob_web = env.person("bob").await;
    // The link is remembered across the redirect; the preview names the room.
    assert_eq!(bob_web.get(&link).await.status(), 303);
    let p = bob_web.get_json("/api/invite").await;
    assert_eq!(p["invite"]["room"], json!("pair"), "{p}");
    assert_eq!(p["invite"]["owner"], json!("roman"));
    let r = bob_web.post_api("/api/invite/accept", None).await;
    assert_eq!(r.status(), 200, "join");

    let j = bob.ok("room_request_join", json!({"room": "pair"})).await;
    assert_eq!(j["status"], json!("member"), "admitted at once: {j}");

    // One use counted: the link cannot be used again.
    let carol = env.person("carol").await;
    assert_eq!(open_and_join(&carol, &link).await, 403, "used up");
    let list = env
        .person("roman")
        .await
        .get_json("/api/rooms/pair/invites")
        .await;
    assert_eq!(list["invites"], json!([]), "no open invites left: {list}");
    // The raw token is never stored.
    let token = query_param(&link, "invite").expect("token");
    assert!(!env.all_text_values().await.contains(&token));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_invite_other_org() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude").await;
    roman
        .ok(
            "room_create",
            json!({"name": "pair", "topic": "Pair on the checkout"}),
        )
        .await;
    let (link, _) = invite(&env, "roman", "pair").await;

    let eve_agent = env.agent_in("eve", "codex", "other.com").await;
    let eve = env.person_in("eve", "other.com").await;
    assert_eq!(eve.get(&link).await.status(), 303);
    let p = eve.get_json("/api/invite").await;
    assert_eq!(p["invite"], Value::Null, "nothing shown: {p}");
    assert!(p["error"].as_str().unwrap_or("").contains("not valid"));
    assert_eq!(eve.get(&link).await.status(), 303);
    assert_eq!(eve.post_api("/api/invite/accept", None).await.status(), 403);
    assert_eq!(
        eve_agent
            .err("room_request_join", json!({"room": "pair"}))
            .await,
        "room_not_found",
        "the room stays invisible to another organization"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_invite_revoked() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude").await;
    roman
        .ok(
            "room_create",
            json!({"name": "pair", "topic": "Pair on the checkout"}),
        )
        .await;
    let (link, id) = invite(&env, "roman", "pair").await;
    let r = env
        .person("roman")
        .await
        .post_api(&format!("/api/rooms/pair/invites/{id}/revoke"), None)
        .await;
    assert_eq!(r.status(), 200, "revoke");

    let bob = env.agent("bob", "codex").await;
    let bob_web = env.person("bob").await;
    assert_eq!(open_and_join(&bob_web, &link).await, 403);
    let j = bob.ok("room_request_join", json!({"room": "pair"})).await;
    assert_eq!(j["status"], json!("pending"), "no access: {j}");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_pair_invite_removal() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude").await;
    roman
        .ok(
            "room_create",
            json!({"name": "pair", "topic": "Pair on the checkout"}),
        )
        .await;
    let (link, _) = invite(&env, "roman", "pair").await;
    let bob = env.agent("bob", "codex").await;
    let bob_web = env.person("bob").await;
    // A request made before the invite is confirmed by Join.
    let early = bob.ok("room_request_join", json!({"room": "pair"})).await;
    assert_eq!(early["status"], json!("pending"));
    assert_eq!(open_and_join(&bob_web, &link).await, 200);
    assert_eq!(
        bob.room_status("pair").await.expect("listed")["status"],
        json!("member"),
        "the pending request was confirmed by Join"
    );

    env.remove("roman", "pair", "bob/codex").await;
    let again = bob.ok("room_request_join", json!({"room": "pair"})).await;
    assert_eq!(
        again["status"],
        json!("pending"),
        "removal withdrew the invite access: {again}"
    );
}
