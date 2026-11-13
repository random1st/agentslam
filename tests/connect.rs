//! uc.agentslam.connect — SSO + OAuth for MCP clients.
mod common;

use common::*;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_discovery() {
    let env = Env::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/mcp", env.base))
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 401);
    let www = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let prm_url = format!("{}/.well-known/oauth-protected-resource/mcp", env.base);
    assert!(www.starts_with("Bearer "), "{www}");
    assert!(
        www.contains(&format!("resource_metadata=\"{prm_url}\"")),
        "{www}"
    );

    let prm: Value = reqwest::get(&prm_url)
        .await
        .expect("prm")
        .json()
        .await
        .expect("json");
    assert_eq!(prm["resource"], json!(format!("{}/mcp", env.base)));
    assert_eq!(prm["authorization_servers"], json!([env.base]));

    let asm: Value = reqwest::get(format!(
        "{}/.well-known/oauth-authorization-server",
        env.base
    ))
    .await
    .expect("as metadata")
    .json()
    .await
    .expect("json");
    assert_eq!(asm["issuer"], json!(env.base));
    assert_eq!(asm["client_id_metadata_document_supported"], json!(true));
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        asm["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert!(
        asm.get("registration_endpoint").is_none(),
        "no DCR endpoint"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_cimd_login() {
    let env = Env::start().await;
    let client_id = env.cimd.client("claude.json");
    let (verifier, challenge) = pkce();
    // Loopback redirect on a "random" port; the metadata lists it without a port.
    let redirect = "http://localhost:61234/callback";
    let b = env.browser();
    let r = b
        .get(&authorize_url(
            &env.base,
            &client_id,
            redirect,
            &challenge,
            "client-state",
        ))
        .await;
    assert_eq!(r.status(), 303);
    let login = location(&r);
    assert!(login.starts_with("/login?req="), "{login}");
    let req = query_param(&format!("{}{login}", env.base), "req").expect("req");

    // The sign-in page names the agent that started it.
    let login_html = b.get(&login).await.text().await.expect("login html");
    assert!(login_html.contains("Claude Code"), "{login_html}");

    env.google
        .set_claims(json!({"sub": "g-roman", "email": "roman@example.com", "hd": "example.com"}));
    let r = b.sign_in(&env, "google", Some(&req)).await;
    assert_eq!(r.status(), 303);
    // No page asks for a name: sign-in continues straight to consent.
    let consent = location(&r);
    assert!(consent.starts_with("/consent?req="), "{consent}");
    let page = b.get(&consent).await.text().await.expect("consent html");
    assert!(
        page.contains("<strong>Claude Code</strong> wants to act as you in agentslam rooms"),
        "consent says what is granted"
    );
    assert!(
        page.contains("value=\"claude-code\""),
        "sensible default agent name"
    );
    assert!(page.contains("roman/"), "shows how the agent will appear");
    let back = b.approve_consent(&consent, "claude-pm").await;
    assert!(
        back.starts_with("http://localhost:61234/callback?"),
        "{back}"
    );
    assert_eq!(query_param(&back, "state").as_deref(), Some("client-state"));
    assert_eq!(
        query_param(&back, "iss").as_deref(),
        Some(env.base.as_str())
    );
    let code = query_param(&back, "code").expect("code");

    let resp = exchange_code(&env.base, &client_id, &code, &verifier, redirect).await;
    assert_eq!(resp.status(), 200);
    let tok: Value = resp.json().await.expect("json");
    let access = tok["access_token"].as_str().expect("access token");
    assert!(tok["refresh_token"].as_str().is_some_and(|r| !r.is_empty()));
    assert_eq!(tok["token_type"], json!("Bearer"));

    let mcp = Mcp::new(&env.base, access);
    mcp.initialize().await;
    // Identity comes from the token only: spoofing arguments are ignored.
    let list = mcp
        .ok(
            "room_list",
            json!({"caller": "alex/codex", "agent": "alex/codex", "as": "alex/codex"}),
        )
        .await;
    assert_eq!(list["caller"], json!("roman/claude-pm"));
    let created = mcp
        .ok("room_create", json!({"name": "ios", "owner": "alex"}))
        .await;
    assert_eq!(created["owner"], json!("roman"));

    // Token is bound to /mcp: the stored resource is the MCP resource.
    let resources: Vec<String> = env
        .server
        .state
        .db
        .call(|c| {
            let mut s = c.prepare("SELECT DISTINCT resource FROM tokens")?;
            Ok(s.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?)
        })
        .await
        .expect("db");
    assert_eq!(resources, vec![format!("{}/mcp", env.base)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_unknown_client() {
    let env = Env::start().await;
    let (_, challenge) = pkce();
    let stranger = env.cimd.client("stranger.json");
    let b = env.browser();
    let r = b
        .get(&authorize_url(
            &env.base,
            &stranger,
            "http://localhost:5000/callback",
            &challenge,
            "s",
        ))
        .await;
    assert_eq!(r.status(), 400);
    assert!(r.headers().get("location").is_none(), "no redirect");
    let body: Value = r.json().await.expect("json");
    assert_eq!(body["error"], json!("invalid_client"));
    assert_eq!(
        env.cimd.hits("stranger.json"),
        0,
        "non-allowlisted metadata is never fetched"
    );
    // And there is no way to reach a consent page for it.
    let page = b.get("/consent?req=anything").await;
    assert_ne!(page.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_bad_redirect() {
    let env = Env::start().await;
    let (_, challenge) = pkce();
    let client = env.cimd.client("claude.json");
    let b = env.person("roman").await;
    for bad in [
        "https://evil.example.com/callback",
        "http://localhost:9999/elsewhere",
        "http://attacker.test/callback",
    ] {
        let r = b
            .get(&authorize_url(&env.base, &client, bad, &challenge, "s"))
            .await;
        assert_eq!(r.status(), 400, "{bad}");
        assert!(
            r.headers().get("location").is_none(),
            "never redirect to {bad}"
        );
        let body: Value = r.json().await.expect("json");
        assert_eq!(body["error"], json!("invalid_request"));
    }
    let codes: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM auth_codes", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(codes, 0, "no code issued");
}

/// Start an OAuth request signed out, sign in via `provider`; returns (browser, req, callback response).
async fn oauth_sign_in(
    env: &Env,
    provider: &str,
    claims: Value,
) -> (Browser, String, reqwest::Response) {
    let (_, challenge) = pkce();
    let b = env.browser();
    let r = b
        .get(&authorize_url(
            &env.base,
            &env.cimd.client("claude.json"),
            CLAUDE_REDIRECT,
            &challenge,
            "s",
        ))
        .await;
    assert_eq!(r.status(), 303);
    let req = query_param(&format!("{}{}", env.base, location(&r)), "req").expect("req");
    env.idp(provider).set_claims(claims);
    let cb = b.sign_in(env, provider, Some(&req)).await;
    (b, req, cb)
}

async fn assert_no_codes(env: &Env) {
    let codes: i64 = env
        .server
        .state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM auth_codes", [], |r| r.get(0))?))
        .await
        .expect("db");
    assert_eq!(codes, 0, "no authorization code issued");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_wrong_domain() {
    let env = Env::start().await;
    for claims in [
        json!({"sub": "g-x", "email": "x@gmail.com"}),
        json!({"sub": "g-y", "email": "y@other.com", "hd": "other.com"}),
    ] {
        let (b, req, cb) = oauth_sign_in(&env, "google", claims).await;
        assert_eq!(cb.status(), 403);
        assert!(cb.headers().get("location").is_none());
        let html = cb.text().await.expect("html");
        assert!(
            html.contains("This account isn&#39;t allowed here"),
            "{html}"
        );
        // No session, so no consent page and no code.
        let consent = b.get(&format!("/consent?req={req}")).await;
        assert_eq!(consent.status(), 303);
        assert!(location(&consent).starts_with("/login"));
    }
    assert_no_codes(&env).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_okta_login() {
    let env = Env::start().await;
    let (b, _req, cb) = oauth_sign_in(
        &env,
        "okta",
        json!({"sub": "okta-1", "email": "o1@example.com", "groups": ["agents", "eng"]}),
    )
    .await;
    assert_eq!(cb.status(), 303);
    let consent = location(&cb);
    assert!(consent.starts_with("/consent?req="), "{consent}");
    let page = b.get(&consent).await;
    assert_eq!(page.status(), 200, "first user reaches the consent page");
    assert!(
        page.text()
            .await
            .expect("html")
            .contains("wants to act as you in agentslam rooms")
    );

    let (_, _, cb2) = oauth_sign_in(
        &env,
        "okta",
        json!({"sub": "okta-2", "email": "o2@example.com", "groups": ["eng"]}),
    )
    .await;
    assert_eq!(cb2.status(), 403);
    assert!(cb2.text().await.expect("html").contains("Access denied"));
    assert_no_codes(&env).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_entra_tenant() {
    let env = Env::start().await;
    let (b, _req, cb) = oauth_sign_in(
        &env,
        "entra",
        json!({"sub": "e-1", "tid": "T", "email": "e1@example.com"}),
    )
    .await;
    assert_eq!(cb.status(), 303);
    let page = b.get(&location(&cb)).await;
    assert_eq!(page.status(), 200, "tenant T reaches consent");

    let (_, _, cb2) = oauth_sign_in(
        &env,
        "entra",
        json!({"sub": "e-2", "tid": "OTHER", "email": "e2@example.com"}),
    )
    .await;
    assert_eq!(cb2.status(), 403);
    assert!(cb2.text().await.expect("html").contains("Access denied"));
    assert_no_codes(&env).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_no_email_merge() {
    let env = Env::start().await;
    let roman = env.agent("roman", "claude-pm").await;
    roman.ok("room_create", json!({"name": "ios"})).await;

    let b = env.browser();
    env.entra
        .set_claims(json!({"sub": "entra-roman", "tid": "T", "email": "roman@example.com"}));
    let cb = b.sign_in(&env, "entra", None).await;
    assert_eq!(cb.status(), 303);
    assert_eq!(location(&cb), "/", "no page asks for a name");
    // A new person, not roman: the email only names it, with a suffix on collision.
    let me = b.get_json("/api/me").await;
    assert_eq!(me["handle"], json!("roman-2"));
    assert_eq!(me["agents"], json!([]), "no access to roman's agents");
    let rooms = b.get_json("/api/rooms").await;
    assert_eq!(rooms["rooms"], json!([]), "no access to roman's rooms");
    assert_eq!(b.get("/api/rooms/ios").await.status(), 403);
}

/// Not an acceptance criterion (B1): the person's name is derived from the
/// email at first sign-in — odd characters become dashes, a collision gets a
/// numeric suffix — and no page asks for it.
#[tokio::test(flavor = "multi_thread")]
async fn handle_is_derived_from_email_with_suffix_on_collision() {
    let env = Env::start().await;
    let mut names = Vec::new();
    for (sub, email) in [
        ("g-1", "R.Voronin+agents@example.com"),
        ("g-2", "r_voronin@example.com"),
        ("g-3", "--@example.com"),
    ] {
        let b = env.browser();
        env.google
            .set_claims(json!({"sub": sub, "email": email, "hd": "example.com"}));
        let cb = b.sign_in(&env, "google", None).await;
        assert_eq!(cb.status(), 303);
        assert_eq!(location(&cb), "/");
        names.push(b.get_json("/api/me").await["handle"].clone());
        // Signing in again keeps the same name.
        let again = env.browser();
        let cb = again.sign_in(&env, "google", None).await;
        assert_eq!(location(&cb), "/");
        assert_eq!(
            again.get_json("/api/me").await["handle"],
            *names.last().expect("name")
        );
    }
    assert_eq!(
        names,
        vec![json!("r-voronin-agents"), json!("r-voronin"), json!("user")]
    );

    let b = env.browser();
    env.google
        .set_claims(json!({"sub": "g-4", "email": "r.voronin@example.com", "hd": "example.com"}));
    b.sign_in(&env, "google", None).await;
    assert_eq!(b.get_json("/api/me").await["handle"], json!("r-voronin-2"));
}

/// Not an acceptance criterion: the old name-picking page is gone.
#[tokio::test(flavor = "multi_thread")]
async fn handle_page_is_removed() {
    let env = Env::start().await;
    let b = env.person("roman").await;
    assert_eq!(b.get("/handle").await.status(), 404);
    assert_eq!(
        b.post_form("/handle", &[("handle", "x")]).await.status(),
        404
    );
    let html = b.get("/login").await.text().await.expect("login html");
    assert!(
        !html.to_lowercase().contains("handle"),
        "no jargon on the sign-in page"
    );
}

/// Not an acceptance criterion: an invalid agent name is explained next to the
/// field, the typed value is kept, and nothing is issued.
#[tokio::test(flavor = "multi_thread")]
async fn consent_invalid_agent_name_is_explained() {
    let env = Env::start().await;
    let b = env.person("roman").await;
    let (_, challenge) = pkce();
    let r = b
        .get(&authorize_url(
            &env.base,
            &env.cimd.client("codex.json"),
            "http://127.0.0.1:5555/callback/xyz",
            &challenge,
            "s",
        ))
        .await;
    let consent = location(&r);
    let html = b.get(&consent).await.text().await.expect("consent");
    assert!(html.contains("value=\"codex\""), "Codex default name");
    let csrf = extract_input(&html, "csrf").expect("csrf");
    let req = extract_input(&html, "req").expect("req");
    let r = b
        .post_form(
            "/consent",
            &[
                ("csrf", &csrf),
                ("req", &req),
                ("label", "Bad Name!"),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_eq!(r.status(), 400);
    let html = r.text().await.expect("html");
    assert!(html.contains("aria-invalid=\"true\""));
    assert!(html.contains("value=\"Bad Name!\""), "typed value kept");
    assert_no_codes(&env).await;
    // The same request still works with a valid name.
    let back = b.approve_consent(&consent, "codex-laptop").await;
    assert!(query_param(&back, "code").is_some());
}

async fn code_for_roman(env: &Env, challenge: &str) -> String {
    let b = env.person("roman").await;
    let back = b
        .authorize_and_consent(
            &env.cimd.client("claude.json"),
            CLAUDE_REDIRECT,
            challenge,
            "claude-pm",
        )
        .await;
    query_param(&back, "code").expect("code")
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_pkce_mismatch() {
    let env = Env::start().await;
    let client = env.cimd.client("claude.json");
    let (verifier, challenge) = pkce();

    let code = code_for_roman(&env, &challenge).await;
    let r = exchange_code(
        &env.base,
        &client,
        &code,
        "wrong-verifier-0123456789012345678901234567890123",
        CLAUDE_REDIRECT,
    )
    .await;
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.expect("json");
    assert_eq!(body["error"], json!("invalid_grant"));
    assert!(body.get("access_token").is_none());

    let code = code_for_roman(&env, &challenge).await;
    let r = exchange_code(&env.base, &client, &code, &verifier, CLAUDE_REDIRECT).await;
    assert_eq!(r.status(), 200);
    let r = exchange_code(&env.base, &client, &code, &verifier, CLAUDE_REDIRECT).await;
    assert_eq!(r.status(), 400, "code is single-use");
    let body: Value = r.json().await.expect("json");
    assert_eq!(body["error"], json!("invalid_grant"));
    assert!(body.get("access_token").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_refresh_rotation() {
    let env = Env::start().await;
    let client = env.cimd.client("claude.json");
    let (verifier, challenge) = pkce();
    let code = code_for_roman(&env, &challenge).await;
    let first: Value = exchange_code(&env.base, &client, &code, &verifier, CLAUDE_REDIRECT)
        .await
        .json()
        .await
        .expect("json");
    let old_refresh = first["refresh_token"].as_str().expect("rt").to_string();

    let r = refresh(&env.base, &client, &old_refresh).await;
    assert_eq!(r.status(), 200);
    let second: Value = r.json().await.expect("json");
    let new_access = second["access_token"].as_str().expect("at");
    assert_ne!(second["refresh_token"], first["refresh_token"]);
    assert_ne!(second["access_token"], first["access_token"]);
    let mcp = Mcp::new(&env.base, new_access);
    assert_eq!(
        mcp.ok("room_list", json!({})).await["caller"],
        json!("roman/claude-pm")
    );

    let r = refresh(&env.base, &client, &old_refresh).await;
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.expect("json");
    assert_eq!(body["error"], json!("invalid_grant"));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_connect_headless_token() {
    let env = Env::start().await;
    let b = env.person("roman").await;
    let (token, family) = b.mint("hermes-ops").await;
    let mcp = Mcp::new(&env.base, &token);
    assert_eq!(
        mcp.ok("room_list", json!({})).await["caller"],
        json!("roman/hermes-ops")
    );

    // Also run an OAuth flow so the DB holds a code, access and refresh tokens.
    let (verifier, challenge) = pkce();
    let client = env.cimd.client("claude.json");
    let code = code_for_roman(&env, &challenge).await;
    let pair: Value = exchange_code(&env.base, &client, &code, &verifier, CLAUDE_REDIRECT)
        .await
        .json()
        .await
        .expect("json");
    let raw = [
        token.clone(),
        code.clone(),
        pair["access_token"].as_str().expect("at").to_string(),
        pair["refresh_token"].as_str().expect("rt").to_string(),
    ];
    let values = env.all_text_values().await;
    for secret in &raw {
        assert!(
            !values.iter().any(|v| v.contains(secret.as_str())),
            "raw secret stored in DB"
        );
    }
    let hashes: Vec<String> = env
        .server
        .state
        .db
        .call(|c| {
            let mut s = c.prepare(
                "SELECT token_hash FROM tokens UNION ALL SELECT code_hash FROM auth_codes",
            )?;
            Ok(s.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?)
        })
        .await
        .expect("db");
    assert!(hashes.len() >= 4);
    assert!(
        hashes
            .iter()
            .all(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
    );

    let r = b
        .post_api(&format!("/api/credentials/{family}/revoke"), None)
        .await;
    assert_eq!(r.status(), 200);
    let (status, _) = mcp
        .rpc_raw("tools/call", json!({"name": "room_list", "arguments": {}}))
        .await;
    assert_eq!(status, 401, "revoked token fails");
}
