//! Headless screenshots of the web UI (not part of `cargo test`: ignored).
//!
//!   AGENTSLAM_PLAYWRIGHT_CLI=/path/to/node_modules/playwright/cli.js \
//!   AGENTSLAM_SHOTS_DIR=~/.diana-work/agentslam-shots \
//!   cargo test --test ui_shots -- --ignored --nocapture
//!
//! Seeds a realistic organization against the in-process server and fake IdP,
//! then captures the rooms page at 1280 and 375 px, with and without data.
mod common;

use std::path::{Path, PathBuf};

use common::*;
use serde_json::json;

fn storage_state(dir: &Path, name: &str, cookie: &str) -> PathBuf {
    let p = dir.join(format!("{name}.storage.json"));
    let body = json!({
        "cookies": [{
            "name": "agentslam_session", "value": cookie, "domain": "127.0.0.1", "path": "/",
            "expires": -1, "httpOnly": true, "secure": false, "sameSite": "Lax"
        }],
        "origins": []
    });
    std::fs::write(&p, body.to_string()).expect("write storage state");
    p
}

async fn shot(cli: &str, storage: &Path, url: &str, out: PathBuf, width: u32, dark: bool) {
    let mut cmd = tokio::process::Command::new("node");
    cmd.arg(cli)
        .arg("screenshot")
        .arg(format!("--load-storage={}", storage.display()));
    if let Ok(channel) = std::env::var("AGENTSLAM_PLAYWRIGHT_CHANNEL") {
        cmd.arg(format!("--channel={channel}"));
    }
    cmd.arg(format!("--viewport-size={width},900"))
        .arg("--wait-for-timeout=1200")
        .arg("--full-page");
    if dark {
        cmd.arg("--color-scheme=dark");
    }
    let status = cmd
        .arg(url)
        .arg(&out)
        .status()
        .await
        .expect("run playwright");
    assert!(status.success(), "screenshot {}", out.display());
    println!("{}", out.display());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node + playwright; run manually for screenshots"]
async fn capture_screenshots() {
    let cli = std::env::var("AGENTSLAM_PLAYWRIGHT_CLI").expect("AGENTSLAM_PLAYWRIGHT_CLI");
    let dir = PathBuf::from(
        std::env::var("AGENTSLAM_SHOTS_DIR").expect("AGENTSLAM_SHOTS_DIR (outside the repo)"),
    );
    std::fs::create_dir_all(&dir).expect("shots dir");
    let env = Env::start().await;

    // With data: roman owns rooms with members, messages, a summary and requests.
    let claude = env.agent("roman", "claude-pm").await;
    let codex = env.agent("roman", "codex").await;
    claude.ok("room_create", json!({"name": "ios"})).await;
    claude.ok("room_create", json!({"name": "backend"})).await;
    claude
        .ok("room_create", json!({"name": "design-review"}))
        .await;
    for text in [
        "Build 1.4.2 is on TestFlight. Crash on launch fixed in AppDelegate.",
        "Push notifications still fail on iOS 17.2 simulators; real devices fine.",
        "I'll take the notification entitlement issue.",
    ] {
        claude
            .ok("room_send", json!({"room": "ios", "text": text}))
            .await;
    }
    claude
        .ok(
            "room_summarize",
            json!({"room": "ios", "text": "- 1.4.2 on TestFlight, launch crash fixed\n- Open: push notifications on 17.2 simulators\n- claude-pm owns the entitlement fix"}),
        )
        .await;
    claude
        .ok(
            "room_send",
            json!({"room": "ios", "text": "Entitlement fix pushed in #482, waiting for review."}),
        )
        .await;
    claude
        .ok(
            "room_send",
            json!({"room": "backend", "text": "Migrated the queue to the new cluster."}),
        )
        .await;
    codex
        .ok("room_request_join", json!({"room": "backend"}))
        .await;
    env.confirm_pending("roman", "backend", "roman/codex").await;
    codex
        .ok(
            "room_send",
            json!({"room": "backend", "text": "Load test at 2k rps passed; p99 140 ms."}),
        )
        .await;
    let alex = env.agent("alex", "codex").await;
    alex.ok("room_request_join", json!({"room": "ios"})).await;
    let bea = env.agent("bea", "cursor").await;
    bea.ok("room_request_join", json!({"room": "backend"}))
        .await;
    claude.ok("room_list", json!({})).await; // presence: online

    let roman = env.person("roman").await;
    let roman_state = storage_state(
        &dir,
        "roman",
        &roman.cookie_value("agentslam_session").expect("cookie"),
    );
    // Without data: a person of the same organization with no agents and no rooms.
    let nina = env.person("nina").await;
    let nina_state = storage_state(
        &dir,
        "nina",
        &nina.cookie_value("agentslam_session").expect("cookie"),
    );

    let base = env.base.clone();
    for (width, tag) in [(1280, "1280"), (375, "375")] {
        shot(
            &cli,
            &roman_state,
            &format!("{base}/"),
            dir.join(format!("rooms-data-{tag}.png")),
            width,
            false,
        )
        .await;
        shot(
            &cli,
            &nina_state,
            &format!("{base}/"),
            dir.join(format!("rooms-empty-{tag}.png")),
            width,
            false,
        )
        .await;
        shot(
            &cli,
            &roman_state,
            &format!("{base}/#room=ios"),
            dir.join(format!("room-ios-{tag}.png")),
            width,
            false,
        )
        .await;
    }
    shot(
        &cli,
        &roman_state,
        &format!("{base}/"),
        dir.join("rooms-data-1280-dark.png"),
        1280,
        true,
    )
    .await;
    shot(
        &cli,
        &roman_state,
        &format!("{base}/#room=ios"),
        dir.join("room-ios-375-dark.png"),
        375,
        true,
    )
    .await;
    // Remove the session files: they hold a live (test-only) session cookie.
    let _ = std::fs::remove_file(&roman_state);
    let _ = std::fs::remove_file(&nina_state);
}
