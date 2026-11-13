//! Hardening from the 2026-11-13 tribunal review: organization binding at
//! sign-in, live streams after logout, bounded room_wait.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

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

/// An identity whose IdP now reports another organization is refused; it is
/// never carried into the organization it first joined.
#[tokio::test(flavor = "multi_thread")]
async fn org_key_change_refuses_sign_in() {
    let env = Env::start().await;
    let _roman = env.person_in("roman", "a.com").await;

    let b = env.browser();
    env.idp("google")
        .set_claims(json!({"sub": "g-roman-a.com", "email": "roman@b.com", "hd": "b.com"}));
    let resp = b.sign_in(&env, "google", None).await;
    assert_eq!(resp.status(), 403, "a moved identity is refused");
    let body = resp.text().await.expect("body");
    assert!(body.contains("Your organization changed"), "{body}");
    assert_eq!(
        b.get("/api/me").await.status(),
        401,
        "no session was created"
    );

    // The refusal sticks: the stored key was not overwritten by the attempt.
    let again = env.browser();
    env.idp("google")
        .set_claims(json!({"sub": "g-roman-a.com", "email": "roman@b.com", "hd": "b.com"}));
    assert_eq!(again.sign_in(&env, "google", None).await.status(), 403);

    // The same identity with its original organization still signs in.
    let ok = env.browser();
    env.idp("google")
        .set_claims(json!({"sub": "g-roman-a.com", "email": "roman@a.com", "hd": "a.com"}));
    let resp = ok.sign_in(&env, "google", None).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/");
}

/// A web stream opened before logout closes on the next event and never
/// delivers a message posted after the session ended.
#[tokio::test(flavor = "multi_thread")]
async fn live_stream_closes_after_logout() {
    let env = Env::start().await;
    let agent = env.agent("roman", "claude").await;
    agent
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release"}),
        )
        .await;
    let b = env.relogin("roman").await;
    let mut stream = b.get("/api/rooms/ios/events").await;
    assert_eq!(stream.status(), 200);
    assert!(
        read_until(&mut stream, "event: ready", Duration::from_secs(5))
            .await
            .is_some()
    );

    let csrf = b.csrf().await;
    let out = b.post_form("/logout", &[("csrf", csrf.as_str())]).await;
    assert_eq!(out.status(), 303);

    agent
        .ok(
            "room_send",
            json!({"room": "ios", "text": "after-logout-secret"}),
        )
        .await;
    let seen = read_until(&mut stream, "access_lost", Duration::from_secs(5))
        .await
        .expect("stream closes with access_lost");
    assert!(
        !seen.contains("after-logout-secret"),
        "no message after logout: {seen}"
    );
}

/// room_wait de-duplicates its rooms and refuses more than 50 distinct ones.
#[tokio::test(flavor = "multi_thread")]
async fn room_wait_is_bounded() {
    let env = Env::start().await;
    let agent = env.agent("roman", "claude").await;
    agent
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release"}),
        )
        .await;

    let many: Vec<String> = (0..51).map(|i| format!("room-{i}")).collect();
    let code = agent
        .err(
            "room_wait",
            json!({"session": "s1", "rooms": many, "timeout_s": 1}),
        )
        .await;
    assert_eq!(code, "bad_request");

    let dup: Vec<&str> = std::iter::repeat_n("ios", 1000).collect();
    let started = Instant::now();
    let r = agent
        .ok(
            "room_wait",
            json!({"session": "s1", "rooms": dup, "timeout_s": 1}),
        )
        .await;
    assert_eq!(r["timed_out"], json!(true), "{r}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// room_list marks topics as untrusted and carries the request policy.
#[tokio::test(flavor = "multi_thread")]
async fn room_list_marks_topics_untrusted() {
    let env = Env::start().await;
    let agent = env.agent("roman", "claude").await;
    agent
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release"}),
        )
        .await;
    let r = agent.ok("room_list", json!({})).await;
    assert_eq!(r["untrusted"], json!(true));
    assert!(
        r["policy"]
            .as_str()
            .unwrap_or_default()
            .contains("Room request policy")
    );
}
