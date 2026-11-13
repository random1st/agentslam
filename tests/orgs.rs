//! uc.agentslam.orgs — self-registered organizations, fully isolated (B13).
mod common;

use agentslam::core::config::AdminIdentity;
use common::*;
use serde_json::{Value, json};

async fn count(env: &Env, sql: &'static str) -> i64 {
    env.server
        .state
        .db
        .call(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?))
        .await
        .expect("db")
}

/// Sign in with `claims` through `provider`; returns the browser and the callback response.
async fn sign_in_as(env: &Env, provider: &str, claims: Value) -> (Browser, reqwest::Response) {
    let b = env.browser();
    env.idp(provider).set_claims(claims);
    let cb = b.sign_in(env, provider, None).await;
    (b, cb)
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_create() {
    let env = Env::start().await;
    assert_eq!(count(&env, "SELECT COUNT(*) FROM organizations").await, 0);
    let (b, cb) = sign_in_as(
        &env,
        "google",
        json!({"sub": "g-1", "email": "ann@example.com", "hd": "example.com"}),
    )
    .await;
    assert_eq!(location(&cb), "/org/create");
    let page = b.get("/org/create").await.text().await.expect("html");
    assert!(page.contains("Create the organization for example.com"));
    // Nothing exists before the person confirms.
    assert_eq!(count(&env, "SELECT COUNT(*) FROM organizations").await, 0);
    assert_eq!(count(&env, "SELECT COUNT(*) FROM persons").await, 0);
    let r = b.complete_org_create(cb).await;
    assert_eq!(location(&r), "/");
    let org = b.get_json("/api/org").await;
    assert_eq!(org["name"], json!("example.com"));
    assert_eq!(org["is_admin"], json!(true));
    assert_eq!(org["admins"], json!(["ann"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_auto_join() {
    let env = Env::start().await;
    env.person_in("ann", "example.com").await; // creates the organization
    let (b, cb) = sign_in_as(
        &env,
        "google",
        json!({"sub": "g-2", "email": "bo@example.com", "hd": "example.com"}),
    )
    .await;
    assert_eq!(location(&cb), "/", "joins without being asked anything");
    let org = b.get_json("/api/org").await;
    assert_eq!(org["name"], json!("example.com"));
    assert_eq!(org["is_admin"], json!(false), "a regular member");
    assert_eq!(count(&env, "SELECT COUNT(*) FROM organizations").await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_isolation() {
    let env = Env::start().await;
    let alice = env.agent_in("alice", "claude-pm", "a.com").await;
    let ann = env.agent_in("ann", "codex", "a.com").await;
    let bob = env.agent_in("bob", "claude-pm", "b.com").await;
    // Room names are unique per organization: both can have "ios".
    alice
        .ok(
            "room_create",
            json!({"name": "ios", "topic": "iOS release coordination"}),
        )
        .await;
    bob.ok(
        "room_create",
        json!({"name": "ios", "topic": "iOS release coordination"}),
    )
    .await;
    bob.ok(
        "room_create",
        json!({"name": "secret-b", "topic": "b.com internal planning"}),
    )
    .await;
    bob.ok("room_send", json!({"room": "ios", "text": "B-PRIVATE"}))
        .await;
    bob.ok(
        "room_send",
        json!({"room": "secret-b", "text": "B-PRIVATE-2"}),
    )
    .await;

    // MCP: room_list shows only a.com's rooms.
    let list = ann.ok("room_list", json!({})).await;
    let rooms: Vec<(&str, &str)> = list["rooms"]
        .as_array()
        .expect("rooms")
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or(""),
                r["owner"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(rooms, vec![("ios", "alice")]);
    assert!(!list.to_string().contains("bob"));
    // room_request_join reaches a.com's ios; b.com's rooms are not found.
    assert_eq!(
        ann.ok("room_request_join", json!({"room": "ios"})).await["status"],
        json!("pending")
    );
    assert_eq!(
        ann.err("room_request_join", json!({"room": "secret-b"}))
            .await,
        "room_not_found"
    );
    assert_eq!(
        ann.err("room_read", json!({"room": "ios", "since": 0}))
            .await,
        "not_a_member"
    );
    assert_eq!(
        ann.err("room_read", json!({"room": "secret-b", "since": 0}))
            .await,
        "room_not_found"
    );
    let read = alice
        .ok("room_read", json!({"room": "ios", "since": 0}))
        .await;
    assert!(!read.to_string().contains("B-PRIVATE"), "a.com's ios only");
    for tool in ["room_send", "room_summarize"] {
        assert_eq!(
            alice
                .err(tool, json!({"room": "secret-b", "text": "x"}))
                .await,
            "room_not_found"
        );
    }

    // Web API: only a.com, b.com's rooms/requests/stream/credentials unreachable.
    let alice_web = env.person_in("alice", "a.com").await;
    let html_rooms = alice_web.get_json("/api/rooms").await;
    assert_eq!(html_rooms["rooms"].as_array().map(Vec::len), Some(1));
    assert!(!html_rooms.to_string().contains("bob"));
    assert_eq!(alice_web.get("/api/rooms/secret-b").await.status(), 404);
    assert_eq!(
        alice_web.get("/api/rooms/secret-b/events").await.status(),
        404
    );
    let detail = alice_web.get_json("/api/rooms/ios").await;
    assert!(!detail.to_string().contains("B-PRIVATE") && !detail.to_string().contains("bob"));
    let reqs = alice_web.get_json("/api/requests").await;
    assert!(!reqs.to_string().contains("bob"));
    // b.com's pending request is not addressable from a.com, even by id.
    ann.ok("room_request_join", json!({"room": "ios"})).await;
    let carol = env.agent_in("carol", "codex", "b.com").await;
    carol
        .ok("room_request_join", json!({"room": "secret-b"}))
        .await;
    let b_req: i64 = count(
        &env,
        "SELECT j.id FROM join_requests j JOIN rooms r ON r.id = j.room_id WHERE r.name = 'secret-b'",
    )
    .await;
    for path in [
        format!("/api/rooms/secret-b/requests/{b_req}/confirm"),
        format!("/api/rooms/ios/requests/{b_req}/confirm"),
        "/api/rooms/secret-b/delete".to_string(),
    ] {
        let r = alice_web.post_api(&path, None).await;
        assert!(
            r.status() == 404 || r.status() == 409,
            "{path}: {}",
            r.status()
        );
    }
    assert_eq!(
        count(&env, "SELECT COUNT(*) FROM memberships m JOIN rooms r ON r.id = m.room_id WHERE r.name = 'secret-b' AND m.status = 'member'").await,
        1,
        "b.com membership unchanged"
    );
    let bob_family: String = env
        .server
        .state
        .db
        .call(|c| {
            Ok(c.query_row(
                "SELECT t.family_id FROM tokens t JOIN agents a ON a.id = t.agent_id
                 JOIN persons p ON p.id = a.person_id WHERE p.handle = 'bob'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("family");
    let r = alice_web
        .post_api(&format!("/api/credentials/{bob_family}/revoke"), None)
        .await;
    assert_eq!(
        r.status(),
        404,
        "an admin of a.com cannot revoke b.com's agent"
    );
    assert!(
        bob.ok("room_list", json!({})).await["rooms"].is_array(),
        "bob still works"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_no_hd() {
    let env = Env::start().await;
    let (_b, cb) = sign_in_as(
        &env,
        "google",
        json!({"sub": "g-personal", "email": "someone@gmail.com"}),
    )
    .await;
    assert_eq!(cb.status(), 403);
    let html = cb.text().await.expect("html");
    assert!(html.contains("A company account is needed"), "{html}");
    assert!(html.contains("Google Workspace"), "explains what is needed");
    assert_eq!(count(&env, "SELECT COUNT(*) FROM persons").await, 0);
    assert_eq!(count(&env, "SELECT COUNT(*) FROM identities").await, 0);
    assert_eq!(count(&env, "SELECT COUNT(*) FROM organizations").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_entra_tenant() {
    let env = Env::start().await;
    let (b1, cb) = sign_in_as(
        &env,
        "entra-multi",
        json!({"sub": "e-1", "tid": "tenant-1", "email": "eve@contoso.com"}),
    )
    .await;
    assert_eq!(
        location(&cb),
        "/org/create",
        "no organization for the tenant yet"
    );
    let r = b1.complete_org_create(cb).await;
    assert_eq!(location(&r), "/");
    let org = b1.get_json("/api/org").await;
    assert_eq!(org["is_admin"], json!(true));
    let (b2, cb2) = sign_in_as(
        &env,
        "entra-multi",
        json!({"sub": "e-2", "tid": "tenant-1", "email": "max@contoso.com"}),
    )
    .await;
    assert_eq!(
        location(&cb2),
        "/",
        "second person of the tenant joins automatically"
    );
    assert_eq!(b2.get_json("/api/org").await["is_admin"], json!(false));
    assert_eq!(
        count(&env, "SELECT COUNT(*) FROM organizations WHERE key_kind = 'entra_tid' AND key_value = 'tenant-1'").await,
        1
    );
    // Another tenant is another organization.
    let (_b3, cb3) = sign_in_as(
        &env,
        "entra-multi",
        json!({"sub": "e-3", "tid": "tenant-2", "email": "x@fabrikam.com"}),
    )
    .await;
    assert_eq!(location(&cb3), "/org/create");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_okta_connect() {
    let env = Env::start().await;
    let admin = env.person_in("ann", "example.com").await;
    let member = env.person_in("bo", "example.com").await;
    let body = json!({"issuer": env.okta.url, "client_id": "agentslam-okta", "client_secret": "test-secret"});
    assert_eq!(
        member
            .post_api("/api/org/okta", Some(body.clone()))
            .await
            .status(),
        403,
        "only an org admin connects Okta"
    );
    let r = admin.post_api("/api/org/okta", Some(body)).await;
    assert_eq!(r.status(), 201);
    let created: Value = r.json().await.expect("json");
    assert!(!created.to_string().contains("test-secret"));
    let id = created["id"].as_i64().expect("id");
    let org = admin.get_json("/api/org").await;
    assert_eq!(
        org["okta_connections"][0]["client_id"],
        json!("agentslam-okta")
    );
    assert!(
        !org.to_string().contains("test-secret"),
        "secret never returned"
    );
    let values = env.all_text_values().await;
    assert!(
        !values.iter().any(|v| v.contains("test-secret")),
        "secret stored only encrypted"
    );

    // A person signing in through the connection joins example.com.
    let b = env.browser();
    env.okta
        .set_claims(json!({"sub": "okta-77", "email": "kim@corp.example"}));
    let r = b.get(&format!("/login/okta/{id}")).await;
    assert_eq!(r.status(), 303);
    let r = b.get(&location(&r)).await; // /login/okta-conn-<id> → IdP
    assert_eq!(r.status(), 303);
    let r = b.get(&location(&r)).await; // IdP → callback
    let cb = b.get(&location(&r)).await;
    assert_eq!(location(&cb), "/", "joins without creating anything");
    let me = b.get_json("/api/me").await;
    assert_eq!(me["org"]["name"], json!("example.com"));
    let html = b.get_json("/api/org").await;
    assert!(!html.to_string().contains("test-secret"));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_oidc_claim() {
    let env = Env::start().await;
    let (b1, cb) = sign_in_as(
        &env,
        "oidc",
        json!({"sub": "o-1", "email": "a@acme.test", "org_id": "acme"}),
    )
    .await;
    assert_eq!(location(&cb), "/org/create");
    let page = b1.get("/org/create").await.text().await.expect("html");
    assert!(page.contains("Create the organization for acme"));
    b1.complete_org_create(cb).await;
    let token = b1.mint("claude-pm").await.0;
    Mcp::new(&env.base, &token)
        .ok(
            "room_create",
            json!({"name": "acme-room", "topic": "acme team room"}),
        )
        .await;

    let (b2, cb2) = sign_in_as(
        &env,
        "oidc",
        json!({"sub": "o-2", "email": "b@acme.test", "org_id": "acme"}),
    )
    .await;
    assert_eq!(location(&cb2), "/", "second person joins acme");
    assert_eq!(b2.get_json("/api/org").await["name"], json!("acme"));

    let (b3, cb3) = sign_in_as(
        &env,
        "oidc",
        json!({"sub": "o-3", "email": "c@other.test", "org_id": "other"}),
    )
    .await;
    assert_eq!(location(&cb3), "/org/create", "a separate organization");
    b3.complete_org_create(cb3).await;
    let rooms = b3.get_json("/api/rooms").await;
    assert_eq!(rooms["rooms"], json!([]), "sees nothing of acme");
    let other_agent = Mcp::new(&env.base, &b3.mint("codex").await.0);
    assert!(
        !other_agent
            .call("room_list", json!({}))
            .await
            .to_string()
            .contains("acme-room")
    );
    assert_eq!(
        other_agent
            .err("room_request_join", json!({"room": "acme-room"}))
            .await,
        "room_not_found"
    );

    let (_b4, cb4) = sign_in_as(&env, "oidc", json!({"sub": "o-4", "email": "d@x.test"})).await;
    assert_eq!(cb4.status(), 403, "an ID token without org_id is refused");
    assert!(cb4.text().await.expect("html").contains("Access denied"));
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_headless_token() {
    let env = Env::start().await;
    let a_person = env.person_in("alice", "a.com").await;
    let token = a_person.mint("hermes-ops").await.0;
    let a_agent = Mcp::new(&env.base, &token);
    a_agent
        .ok(
            "room_create",
            json!({"name": "alpha", "topic": "a.com alpha project"}),
        )
        .await;
    let bob = env.agent_in("bob", "claude-pm", "b.com").await;
    bob.ok(
        "room_create",
        json!({"name": "beta", "topic": "b.com beta project"}),
    )
    .await;

    let list = a_agent.ok("room_list", json!({})).await;
    let names: Vec<&str> = list["rooms"]
        .as_array()
        .expect("rooms")
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert_eq!(names, vec!["alpha"]);
    assert_eq!(list["caller"], json!("alice/hermes-ops"));
    assert_eq!(
        a_agent
            .err("room_request_join", json!({"room": "beta"}))
            .await,
        "room_not_found"
    );
    // The hook endpoint with the same token is scoped too.
    let r = reqwest::Client::new()
        .post(format!("{}/hook/stop", env.base))
        .bearer_auth(&token)
        .json(&json!({"session_id": "S"}))
        .send()
        .await
        .expect("hook");
    assert_eq!(r.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_restrict() {
    let env = Env::start_with(|c| c.allowed_domains = vec!["example.org".into()]).await;
    let (_b, cb) = sign_in_as(
        &env,
        "google",
        json!({"sub": "g-o", "email": "x@other.com", "hd": "other.com"}),
    )
    .await;
    assert_eq!(cb.status(), 403);
    assert!(
        cb.text()
            .await
            .expect("html")
            .contains("can&#39;t use this server")
    );
    assert_eq!(count(&env, "SELECT COUNT(*) FROM organizations").await, 0);
    assert_eq!(count(&env, "SELECT COUNT(*) FROM persons").await, 0);
    // The allowed domain can register.
    let (b, cb) = sign_in_as(
        &env,
        "google",
        json!({"sub": "g-q", "email": "r@example.org", "hd": "example.org"}),
    )
    .await;
    assert_eq!(location(&b.complete_org_create(cb).await), "/");
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_org_oidc_fixed() {
    let env = Env::start().await;
    // No organization claim in either ID token.
    let (b1, cb) = sign_in_as(
        &env,
        "oidc-fixed",
        json!({"sub": "k-1", "email": "a@acme.test"}),
    )
    .await;
    assert_eq!(location(&cb), "/org/create", "first person creates acme");
    let page = b1.get("/org/create").await.text().await.expect("html");
    assert!(page.contains("Create the organization for acme"), "{page}");
    assert_eq!(location(&b1.complete_org_create(cb).await), "/");
    let org = b1.get_json("/api/org").await;
    assert_eq!(org["name"], json!("acme"));
    assert_eq!(org["is_admin"], json!(true));

    let (b2, cb2) = sign_in_as(
        &env,
        "oidc-fixed",
        json!({"sub": "k-2", "email": "b@elsewhere.test"}),
    )
    .await;
    assert_eq!(
        location(&cb2),
        "/",
        "second person joins acme automatically"
    );
    let org2 = b2.get_json("/api/org").await;
    assert_eq!(org2["name"], json!("acme"));
    assert_eq!(org2["is_admin"], json!(false));
    let key = format!("{}#acme", env.oidc_fixed.url);
    let orgs: i64 = env
        .server
        .state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM organizations WHERE key_kind = 'oidc' AND key_value = ?1",
                [key],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("db");
    assert_eq!(orgs, 1, "keyed by (issuer, name)");
    assert_eq!(count(&env, "SELECT COUNT(*) FROM organizations").await, 1);
}

/// The instance operator (super admin) of a.com, for operator tests.
async fn env_with_operator() -> Env {
    Env::start_with(|c| {
        let iss = c.providers[0].issuer.clone().unwrap_or_default();
        c.admins.push(AdminIdentity {
            issuer: iss,
            sub: "g-op-a.com".into(),
        });
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn s5d_ac_uc_agentslam_orgs_operator_admins() {
    let env = env_with_operator().await;
    let alice_web = env.person_in("alice", "a.com").await; // creates a.com
    let op = env.person_in("op", "a.com").await; // operator, member of a.com
    let op_agent = env.agent_in("op", "claude-pm", "a.com").await;
    let bob = env.agent_in("bob", "claude-pm", "b.com").await; // creates b.com
    let bob_web = env.person_in("bob", "b.com").await;
    let carol_web = env.person_in("carol", "b.com").await;
    bob.ok(
        "room_create",
        json!({"name": "beta", "topic": "b.com beta project"}),
    )
    .await;
    bob.ok("room_send", json!({"room": "beta", "text": "B-SECRET"}))
        .await;
    assert_eq!(
        carol_web.get_json("/api/org").await["is_admin"],
        json!(false)
    );

    let orgs = op.get_json("/api/operator/orgs").await;
    let b_id = orgs["organizations"]
        .as_array()
        .and_then(|o| o.iter().find(|x| x["name"] == "b.com"))
        .and_then(|x| x["id"].as_i64())
        .expect("b.com listed");
    let admins_path = format!("/api/operator/orgs/{b_id}/admins");
    let disable_path = format!("/api/operator/orgs/{b_id}/disable");
    let enable_path = format!("/api/operator/orgs/{b_id}/enable");

    // A non-operator (even b.com's own admin) gets 403; so does a missing CSRF token.
    for who in [&alice_web, &bob_web, &carol_web] {
        assert_eq!(who.get("/api/operator/orgs").await.status(), 403);
        assert_eq!(
            who.post_api(&admins_path, Some(json!({"handle": "carol"})))
                .await
                .status(),
            403
        );
        assert_eq!(who.post_api(&disable_path, None).await.status(), 403);
        assert_eq!(who.post_api(&enable_path, None).await.status(), 403);
    }
    assert_eq!(
        op.post_api_with(&admins_path, Some(json!({"handle": "carol"})), None)
            .await
            .status(),
        403,
        "CSRF"
    );
    assert_eq!(
        carol_web.get_json("/api/org").await["is_admin"],
        json!(false)
    );

    // Name carol (b.com) admin of b.com; a person of another org cannot be named.
    assert_eq!(
        op.post_api(&admins_path, Some(json!({"handle": "carol"})))
            .await
            .status(),
        200
    );
    assert_eq!(
        carol_web.get_json("/api/org").await["is_admin"],
        json!(true)
    );
    assert_eq!(
        op.post_api(&admins_path, Some(json!({"handle": "alice"})))
            .await
            .status(),
        404,
        "alice is not a person of b.com"
    );
    let orgs = op.get_json("/api/operator/orgs").await;
    let b = orgs["organizations"]
        .as_array()
        .and_then(|o| o.iter().find(|x| x["name"] == "b.com"))
        .cloned()
        .expect("b.com");
    assert_eq!(b["admins"], json!(["bob", "carol"]));

    // Disable, then re-enable.
    assert_eq!(op.post_api(&disable_path, None).await.status(), 200);
    let (status, _) = bob
        .rpc_raw("tools/call", json!({"name": "room_list", "arguments": {}}))
        .await;
    assert_eq!(status, 401, "disabled");
    assert_eq!(bob_web.get("/api/me").await.status(), 401);
    assert_eq!(op.post_api(&enable_path, None).await.status(), 200);
    assert!(
        bob.ok("room_list", json!({})).await["rooms"].is_array(),
        "re-enabled"
    );
    assert_eq!(bob_web.get("/api/me").await.status(), 200);
    assert_eq!(
        op.post_api(&enable_path, None).await.status(),
        404,
        "already enabled"
    );

    // The operator still sees no b.com room or message.
    let everything = [
        op.get_json("/api/rooms").await.to_string(),
        op.get_json("/api/requests").await.to_string(),
        op.get_json("/api/operator/orgs").await.to_string(),
        op_agent.call("room_list", json!({})).await.to_string(),
    ]
    .concat();
    assert!(!everything.contains("beta") && !everything.contains("B-SECRET"));
    assert_eq!(op.get("/api/rooms/beta").await.status(), 404);
    assert_eq!(op.get("/api/rooms/beta/events").await.status(), 404);
    assert_eq!(
        op_agent
            .err("room_read", json!({"room": "beta", "since": 0}))
            .await,
        "room_not_found"
    );
    assert_eq!(
        op_agent
            .err("room_request_join", json!({"room": "beta"}))
            .await,
        "room_not_found"
    );
}

/// Not an acceptance criterion: an instance operator disables an organization;
/// its agents and people lose access at once, others are unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn operator_disables_an_organization() {
    let env = Env::start_with(|c| {
        let iss = c.providers[0].issuer.clone().unwrap_or_default();
        c.admins.push(AdminIdentity {
            issuer: iss,
            sub: "g-op-ops.com".into(),
        });
    })
    .await;
    let alice = env.agent_in("alice", "claude-pm", "a.com").await;
    let bob = env.agent_in("bob", "claude-pm", "b.com").await;
    let alice_web = env.person_in("alice", "a.com").await;
    let op = env.person_in("op", "ops.com").await;
    let orgs = op.get_json("/api/operator/orgs").await;
    let a_id = orgs["organizations"]
        .as_array()
        .and_then(|o| o.iter().find(|x| x["name"] == "a.com"))
        .and_then(|x| x["id"].as_i64())
        .expect("a.com listed");
    assert_eq!(
        alice_web.get("/api/operator/orgs").await.status(),
        403,
        "operators only"
    );
    let r = op
        .post_api(&format!("/api/operator/orgs/{a_id}/disable"), None)
        .await;
    assert_eq!(r.status(), 200);
    let (status, _) = alice
        .rpc_raw("tools/call", json!({"name": "room_list", "arguments": {}}))
        .await;
    assert_eq!(status, 401, "a disabled organization's tokens stop working");
    assert_eq!(alice_web.get("/api/me").await.status(), 401);
    assert!(bob.ok("room_list", json!({})).await["rooms"].is_array());
}
