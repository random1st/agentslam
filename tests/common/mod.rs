//! Shared integration-test harness: a fake OIDC IdP (discovery, JWKS, token
//! endpoint issuing RS256 ID tokens with chosen claims), a local CIMD server,
//! a cookie-keeping browser, and a raw JSON-RPC MCP client over Streamable HTTP.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use agentslam::core::Running;
use agentslam::core::config::{Config, OAuthConfig, ProviderConfig, ProviderKind};
use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::header::{HeaderMap, LOCATION, SET_COOKIE};
use serde_json::{Value, json};
use sha2::Digest;

pub const CLAUDE_REDIRECT: &str = "http://localhost:53682/callback";
pub const KID: &str = "test-key-1";

// ------------------------------------------------------------ signing key

struct TestKey {
    pem: String,
    n: String,
    e: String,
}

fn test_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
            .expect("generate test RSA key");
        let pem = key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode test key")
            .to_string();
        TestKey {
            pem,
            n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }
    })
}

async fn spawn(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

// ------------------------------------------------------------ fake IdP

struct IdpState {
    issuer: String,
    client_id: String,
    next_claims: Mutex<Value>,
    codes: Mutex<HashMap<String, (Value, String)>>,
}

#[derive(Clone)]
pub struct FakeIdp {
    pub url: String,
    state: Arc<IdpState>,
}

impl FakeIdp {
    pub async fn start(client_id: &str) -> FakeIdp {
        // Bind first so the issuer URL is known before building routes.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let state = Arc::new(IdpState {
            issuer: url.clone(),
            client_id: client_id.to_string(),
            next_claims: Mutex::new(json!({})),
            codes: Mutex::new(HashMap::new()),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(idp_discovery))
            .route("/jwks", get(idp_jwks))
            .route("/authorize", get(idp_authorize))
            .route("/token", post(idp_token))
            .with_state(state.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        FakeIdp { url, state }
    }

    /// Claims (sub, email, hd, groups, tid, ...) for the next sign-in.
    pub fn set_claims(&self, claims: Value) {
        *self.state.next_claims.lock().expect("lock") = claims;
    }
}

async fn idp_discovery(State(s): State<Arc<IdpState>>) -> Json<Value> {
    Json(json!({
        "issuer": s.issuer,
        "authorization_endpoint": format!("{}/authorize", s.issuer),
        "token_endpoint": format!("{}/token", s.issuer),
        "jwks_uri": format!("{}/jwks", s.issuer),
    }))
}

async fn idp_jwks() -> Json<Value> {
    let k = test_key();
    Json(
        json!({"keys": [{"kty": "RSA", "kid": KID, "alg": "RS256", "use": "sig", "n": k.n, "e": k.e}]}),
    )
}

async fn idp_authorize(
    State(s): State<Arc<IdpState>>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    assert_eq!(
        q.get("client_id").map(String::as_str),
        Some(s.client_id.as_str())
    );
    assert_eq!(
        q.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let code = format!("idp-code-{}", rand_suffix());
    let claims = s.next_claims.lock().expect("lock").clone();
    let nonce = q.get("nonce").cloned().unwrap_or_default();
    s.codes
        .lock()
        .expect("lock")
        .insert(code.clone(), (claims, nonce));
    let mut u = url::Url::parse(q.get("redirect_uri").expect("redirect_uri")).expect("url");
    u.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", q.get("state").map(String::as_str).unwrap_or(""));
    Redirect::to(u.as_str())
}

async fn idp_token(
    State(s): State<Arc<IdpState>>,
    Form(f): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let Some((claims, nonce)) = f
        .get("code")
        .and_then(|c| s.codes.lock().expect("lock").remove(c))
    else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    assert!(
        f.get("client_secret").is_some_and(|c| c == "test-secret"),
        "client secret sent"
    );
    let now = chrono_now();
    let mut body =
        json!({"iss": s.issuer, "aud": s.client_id, "iat": now, "exp": now + 300, "nonce": nonce});
    if let (Some(obj), Some(extra)) = (body.as_object_mut(), claims.as_object()) {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    let key = EncodingKey::from_rsa_pem(test_key().pem.as_bytes()).expect("encoding key");
    let id_token = jsonwebtoken::encode(&header, &body, &key).expect("sign");
    Json(json!({"access_token": "upstream-at", "token_type": "Bearer", "id_token": id_token}))
        .into_response()
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn rand_suffix() -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

// ------------------------------------------------------------ CIMD server

#[derive(Clone)]
pub struct CimdServer {
    pub url: String,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl CimdServer {
    pub async fn start() -> CimdServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let base = url.clone();
        let h = hits.clone();
        let router = Router::new().route(
            "/{name}",
            get(
                move |axum::extract::Path(name): axum::extract::Path<String>| {
                    let base = base.clone();
                    let h = h.clone();
                    async move {
                        *h.lock().expect("lock").entry(name.clone()).or_default() += 1;
                        let (client_name, redirects) = match name.as_str() {
                            "claude.json" => (
                                "Claude Code",
                                vec!["http://localhost/callback", "http://127.0.0.1/callback"],
                            ),
                            "codex.json" => ("Codex", vec!["http://127.0.0.1/callback/xyz"]),
                            _ => ("Stranger", vec!["http://localhost/callback"]),
                        };
                        Json(json!({
                            "client_id": format!("{base}/{name}"),
                            "client_name": client_name,
                            "redirect_uris": redirects,
                            "grant_types": ["authorization_code", "refresh_token"],
                            "response_types": ["code"],
                            "token_endpoint_auth_method": "none",
                        }))
                    }
                },
            ),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        CimdServer { url, hits }
    }

    pub fn client(&self, name: &str) -> String {
        format!("{}/{name}", self.url)
    }

    pub fn hits(&self, name: &str) -> usize {
        self.hits
            .lock()
            .expect("lock")
            .get(name)
            .copied()
            .unwrap_or(0)
    }
}

// ------------------------------------------------------------ environment

pub struct Env {
    pub server: Running,
    pub base: String,
    pub google: FakeIdp,
    pub okta: FakeIdp,
    /// Single-tenant Entra provider (tenant T).
    pub entra: FakeIdp,
    /// Multi-tenant Entra provider (any tid; the organization is the tid).
    pub entra_multi: FakeIdp,
    /// Generic OIDC provider with org_claim = org_id.
    pub oidc: FakeIdp,
    pub cimd: CimdServer,
    people: tokio::sync::Mutex<HashMap<String, Arc<Browser>>>,
}

/// Fixed test key for stored Okta secrets (not a real secret).
pub const TEST_SECRET_KEY: [u8; 32] = [42u8; 32];

fn provider(id: &str, kind: ProviderKind, issuer: &str) -> ProviderConfig {
    ProviderConfig {
        id: id.to_string(),
        kind,
        display_name: None,
        issuer: Some(issuer.to_string()),
        client_id: format!("agentslam-{id}"),
        client_secret_env: None,
        client_secret: Some("test-secret".to_string()),
        allowed_domains: vec![],
        required_group: None,
        tenant_id: None,
        groups_claim: "groups".to_string(),
        admin_group: None,
        org_claim: None,
        org_map: Default::default(),
    }
}

impl Env {
    pub async fn start() -> Env {
        Env::start_with(|_| {}).await
    }

    /// Start with a config tweak (instance restrictions, operators, ...).
    pub async fn start_with(customize: impl FnOnce(&mut Config)) -> Env {
        let google = FakeIdp::start("agentslam-google").await;
        let okta = FakeIdp::start("agentslam-okta").await;
        let entra = FakeIdp::start("agentslam-entra").await;
        let entra_multi = FakeIdp::start("agentslam-entra-multi").await;
        let oidc = FakeIdp::start("agentslam-oidc").await;
        let cimd = CimdServer::start().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let g = provider("google", ProviderKind::Google, &google.url);
        let mut o = provider("okta", ProviderKind::Okta, &okta.url);
        o.required_group = Some("agents".into());
        let mut e = provider("entra", ProviderKind::Entra, &entra.url);
        e.tenant_id = Some("T".into());
        let em = provider("entra-multi", ProviderKind::Entra, &entra_multi.url);
        let mut oi = provider("oidc", ProviderKind::Oidc, &oidc.url);
        oi.org_claim = Some("org_id".into());
        let mut config = Config {
            bind: "127.0.0.1:0".parse().expect("addr"),
            public_url: base.clone(),
            database: ":memory:".into(),
            secure_cookies: false,
            allow_insecure_http_for_tests: true,
            providers: vec![g, o, e, em, oi],
            oauth: OAuthConfig {
                allowed_clients: vec![cimd.client("claude.json"), cimd.client("codex.json")],
                ..OAuthConfig::default()
            },
            admins: vec![],
            summary: Default::default(),
            allowed_domains: vec![],
            allowed_tenants: vec![],
            secret_key: Some(TEST_SECRET_KEY),
        };
        customize(&mut config);
        config.validate().expect("test config valid");
        let server = agentslam::core::app::serve(config, Some(listener))
            .await
            .expect("serve");
        Env {
            server,
            base,
            google,
            okta,
            entra,
            entra_multi,
            oidc,
            cimd,
            people: Default::default(),
        }
    }

    pub fn idp(&self, provider: &str) -> &FakeIdp {
        match provider {
            "google" => &self.google,
            "okta" => &self.okta,
            "entra-multi" => &self.entra_multi,
            "oidc" => &self.oidc,
            _ => &self.entra,
        }
    }

    pub fn browser(&self) -> Browser {
        Browser::new(&self.base)
    }

    /// Signed-in person (Google, hd example.com, sub = g-<handle>, email <handle>@example.com).
    /// The name is derived from the email at first sign-in, so it equals `handle`.
    /// The first person of example.com creates its organization (and is its admin).
    pub async fn person(&self, handle: &str) -> Arc<Browser> {
        self.person_in(handle, "example.com").await
    }

    /// Signed-in person of the Workspace domain `domain` (one organization per domain).
    pub async fn person_in(&self, handle: &str, domain: &str) -> Arc<Browser> {
        let key = format!("{handle}@{domain}");
        let mut people = self.people.lock().await;
        if let Some(b) = people.get(&key) {
            return b.clone();
        }
        let b = self.browser();
        self.google.set_claims(json!({"sub": format!("g-{handle}-{domain}"), "email": format!("{handle}@{domain}"), "hd": domain}));
        let resp = b.sign_in(self, "google", None).await;
        let resp = b.complete_org_create(resp).await;
        assert_eq!(resp.status(), 303, "sign-in redirect");
        assert_eq!(location(&resp), "/", "sign-in ends on the rooms page");
        let me = b.get_json("/api/me").await;
        assert_eq!(me["handle"], json!(handle), "name derived from the email");
        let b = Arc::new(b);
        people.insert(key, b.clone());
        b
    }

    /// Fresh web session for an existing person (e.g. after the clock moved past session expiry).
    pub async fn relogin(&self, handle: &str) -> Browser {
        let b = self.browser();
        self.google.set_claims(json!({"sub": format!("g-{handle}-example.com"), "email": format!("{handle}@example.com"), "hd": "example.com"}));
        let resp = b.sign_in(self, "google", None).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(location(&resp), "/", "existing person signs straight in");
        b
    }

    /// `<handle>/<label>` agent with a headless token minted in the web UI.
    pub async fn agent(&self, handle: &str, label: &str) -> Mcp {
        self.agent_in(handle, label, "example.com").await
    }

    pub async fn agent_in(&self, handle: &str, label: &str, domain: &str) -> Mcp {
        let b = self.person_in(handle, domain).await;
        let token = b.mint(label).await.0;
        Mcp::new(&self.base, &token)
    }

    /// roman/claude-pm owns ios; alex/codex is a confirmed member.
    pub async fn ios_with_alex(&self) -> (Mcp, Mcp) {
        let roman = self.agent("roman", "claude-pm").await;
        let alex = self.agent("alex", "codex").await;
        roman.ok("room_create", json!({"name": "ios"})).await;
        alex.ok("room_request_join", json!({"room": "ios"})).await;
        self.confirm_pending("roman", "ios", "alex/codex").await;
        (roman, alex)
    }

    pub async fn confirm_pending(&self, owner: &str, room: &str, agent: &str) {
        let b = self.person(owner).await;
        let id = b.pending_request_id(room, agent).await;
        let r = b
            .post_api(&format!("/api/rooms/{room}/requests/{id}/confirm"), None)
            .await;
        assert_eq!(r.status(), 200, "confirm");
    }

    pub async fn remove(&self, owner: &str, room: &str, agent: &str) {
        let b = self.person(owner).await;
        let detail = b.get_json(&format!("/api/rooms/{room}")).await;
        let id = detail["members"]
            .as_array()
            .and_then(|m| m.iter().find(|x| x["agent"] == agent))
            .and_then(|x| x["agent_id"].as_i64())
            .expect("member present");
        let r = b
            .post_api(&format!("/api/rooms/{room}/members/{id}/remove"), None)
            .await;
        assert_eq!(r.status(), 200, "remove");
    }

    /// Run an SQL query returning one column of strings over every table/column (for hash checks).
    pub async fn all_text_values(&self) -> Vec<String> {
        self.server
            .state
            .db
            .call(|c| {
                let tables: Vec<String> = {
                    let mut s = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
                    s.query_map([], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                let mut out = Vec::new();
                for t in tables {
                    let mut s = c.prepare(&format!("SELECT * FROM \"{t}\""))?;
                    let n = s.column_count();
                    let mut rows = s.query([])?;
                    while let Some(row) = rows.next()? {
                        for i in 0..n {
                            if let Ok(v) = row.get::<_, String>(i) {
                                out.push(v);
                            }
                        }
                    }
                }
                Ok(out)
            })
            .await
            .expect("db scan")
    }
}

pub fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

pub fn query_param(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
}

pub fn pkce() -> (String, String) {
    let verifier = format!(
        "verifier-{}-abcdefghijklmnopqrstuvwxyz0123456789",
        rand_suffix()
    );
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

// ------------------------------------------------------------ browser

pub struct Browser {
    pub base: String,
    client: reqwest::Client,
    cookies: Mutex<HashMap<String, String>>,
}

impl Browser {
    pub fn new(base: &str) -> Browser {
        Browser {
            base: base.to_string(),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(60))
                .build()
                .expect("client"),
            cookies: Mutex::new(HashMap::new()),
        }
    }

    fn abs(&self, url: &str) -> String {
        if url.starts_with("http") {
            url.to_string()
        } else {
            format!("{}{url}", self.base)
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn store(&self, headers: &HeaderMap) {
        for v in headers.get_all(SET_COOKIE) {
            let Ok(s) = v.to_str() else { continue };
            let first = s.split(';').next().unwrap_or("");
            if let Some((k, val)) = first.split_once('=') {
                let mut c = self.cookies.lock().expect("lock");
                if val.is_empty() || s.contains("Max-Age=0") {
                    c.remove(k);
                } else {
                    c.insert(k.to_string(), val.to_string());
                }
            }
        }
    }

    pub async fn get(&self, url: &str) -> reqwest::Response {
        let url = self.abs(url);
        let mut req = self.client.get(&url);
        if url.starts_with(&self.base) {
            req = req.header("cookie", self.cookie_header());
        }
        let resp = req.send().await.expect("GET");
        self.store(resp.headers());
        resp
    }

    pub async fn get_json(&self, url: &str) -> Value {
        let r = self.get(url).await;
        assert!(r.status().is_success(), "GET {url} -> {}", r.status());
        r.json().await.expect("json")
    }

    pub async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> reqwest::Response {
        let resp = self
            .client
            .post(self.abs(url))
            .header("cookie", self.cookie_header())
            .form(form)
            .send()
            .await
            .expect("POST form");
        self.store(resp.headers());
        resp
    }

    /// POST to the JSON API with the session's CSRF token.
    pub async fn post_api(&self, url: &str, body: Option<Value>) -> reqwest::Response {
        let csrf = self.csrf().await;
        self.post_api_with(url, body, Some(&csrf)).await
    }

    pub async fn post_api_with(
        &self,
        url: &str,
        body: Option<Value>,
        csrf: Option<&str>,
    ) -> reqwest::Response {
        let mut req = self
            .client
            .post(self.abs(url))
            .header("cookie", self.cookie_header());
        if let Some(c) = csrf {
            req = req.header("x-csrf-token", c);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        req.send().await.expect("POST api")
    }

    pub async fn csrf(&self) -> String {
        let me = self.get_json("/api/me").await;
        me["csrf"].as_str().expect("csrf").to_string()
    }

    /// GET /login/<provider> → IdP → callback; returns the callback response.
    pub async fn sign_in(&self, env: &Env, provider: &str, req: Option<&str>) -> reqwest::Response {
        let _ = env;
        let start = match req {
            Some(r) => format!("/login/{provider}?req={r}"),
            None => format!("/login/{provider}"),
        };
        let r = self.get(&start).await;
        assert_eq!(r.status(), 303, "login start redirects to the IdP");
        let r = self.get(&location(&r)).await;
        assert_eq!(r.status(), 303, "IdP redirects back");
        self.get(&location(&r)).await
    }

    /// Current value of a cookie this browser holds (for headless screenshots).
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.cookies.lock().expect("lock").get(name).cloned()
    }

    /// If sign-in led to "Create the organization for …", confirm it and
    /// return the resulting redirect; otherwise return `resp` unchanged.
    pub async fn complete_org_create(&self, resp: reqwest::Response) -> reqwest::Response {
        let loc = location(&resp);
        if resp.status() != 303 || !loc.starts_with("/org/create") {
            return resp;
        }
        let page = self.get(&loc).await;
        assert_eq!(page.status(), 200, "org create page");
        let html = page.text().await.expect("html");
        assert!(html.contains("Create the organization for"), "{html}");
        let csrf = extract_input(&html, "csrf").expect("csrf");
        let req = extract_input(&html, "req").unwrap_or_default();
        self.post_form("/org/create", &[("csrf", &csrf), ("req", &req)])
            .await
    }

    /// Mint a headless agent token; returns (token, family_id).
    pub async fn mint(&self, label: &str) -> (String, String) {
        let r = self
            .post_api("/api/agent-tokens", Some(json!({"label": label})))
            .await;
        assert_eq!(r.status(), 201, "mint");
        let v: Value = r.json().await.expect("json");
        (
            v["token"].as_str().expect("token").to_string(),
            v["family_id"].as_str().expect("family").to_string(),
        )
    }

    pub async fn pending_request_id(&self, room: &str, agent: &str) -> i64 {
        let detail = self.get_json(&format!("/api/rooms/{room}")).await;
        detail["requests"]
            .as_array()
            .and_then(|r| {
                r.iter()
                    .find(|x| x["agent"] == agent && x["status"] == "pending")
            })
            .and_then(|x| x["id"].as_i64())
            .expect("pending request")
    }

    /// Run the OAuth authorization request for an allowlisted client while
    /// signed in; approve consent with `label`. Returns the client redirect URL.
    pub async fn authorize_and_consent(
        &self,
        client_id: &str,
        redirect_uri: &str,
        challenge: &str,
        label: &str,
    ) -> String {
        let r = self
            .get(&authorize_url(
                &self.base,
                client_id,
                redirect_uri,
                challenge,
                "st-1",
            ))
            .await;
        assert_eq!(r.status(), 303, "authorize redirects to consent");
        let consent = location(&r);
        assert!(
            consent.starts_with("/consent?req="),
            "signed-in person goes straight to consent: {consent}"
        );
        self.approve_consent(&consent, label).await
    }

    pub async fn approve_consent(&self, consent_path: &str, label: &str) -> String {
        let page = self.get(consent_path).await;
        assert_eq!(page.status(), 200, "consent page");
        let html = page.text().await.expect("html");
        let csrf = extract_input(&html, "csrf").expect("csrf");
        let req = extract_input(&html, "req").expect("req");
        let r = self
            .post_form(
                "/consent",
                &[
                    ("csrf", &csrf),
                    ("req", &req),
                    ("label", label),
                    ("decision", "approve"),
                ],
            )
            .await;
        assert_eq!(r.status(), 303, "consent redirects to client");
        location(&r)
    }
}

pub fn authorize_url(
    base: &str,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> String {
    let mut u = url::Url::parse(&format!("{base}/authorize")).expect("url");
    u.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("resource", &format!("{base}/mcp"));
    u.to_string()
}

pub fn extract_input(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

pub async fn exchange_code(
    base: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("resource", &format!("{base}/mcp")),
        ])
        .send()
        .await
        .expect("token request")
}

pub async fn refresh(base: &str, client_id: &str, refresh_token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .send()
        .await
        .expect("refresh request")
}

// ------------------------------------------------------------ MCP client

pub struct Mcp {
    pub url: String,
    pub token: String,
    client: reqwest::Client,
}

impl Mcp {
    pub fn new(base: &str, token: &str) -> Mcp {
        Mcp {
            url: format!("{base}/mcp"),
            token: token.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(70))
                .build()
                .expect("client"),
        }
    }

    /// A brand-new client (new HTTP connection pool) with the same token.
    pub fn reconnect(&self) -> Mcp {
        Mcp::new(self.url.trim_end_matches("/mcp"), &self.token)
    }

    /// Raw JSON-RPC request; returns (HTTP status, parsed body or Null).
    pub async fn rpc_raw(&self, method: &str, params: Value) -> (u16, Value) {
        let req = self
            .client
            .post(&self.url)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-11-25")
            .bearer_auth(&self.token)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
        let resp = req.send().await.expect("mcp request");
        let status = resp.status().as_u16();
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let text = resp.text().await.unwrap_or_default();
        let body = if ct.starts_with("text/event-stream") {
            text.lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
                .find(|v| v.get("id").is_some())
                .unwrap_or(Value::Null)
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        (status, body)
    }

    pub async fn initialize(&self) -> Value {
        let (status, body) = self
            .rpc_raw(
                "initialize",
                json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}),
            )
            .await;
        assert_eq!(status, 200, "initialize: {body}");
        body["result"].clone()
    }

    pub async fn tool_names(&self) -> Vec<String> {
        let (status, body) = self.rpc_raw("tools/list", json!({})).await;
        assert_eq!(status, 200, "tools/list: {body}");
        body["result"]["tools"]
            .as_array()
            .map(|t| {
                t.iter()
                    .filter_map(|x| x["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// tools/call; returns the CallToolResult object.
    pub async fn call(&self, tool: &str, args: Value) -> Value {
        let (status, body) = self
            .rpc_raw("tools/call", json!({"name": tool, "arguments": args}))
            .await;
        assert_eq!(status, 200, "tools/call {tool}: HTTP {status} {body}");
        body["result"].clone()
    }

    pub async fn ok(&self, tool: &str, args: Value) -> Value {
        let r = self.call(tool, args).await;
        assert_ne!(r["isError"], json!(true), "{tool} should succeed: {r}");
        r["structuredContent"].clone()
    }

    /// Expect a tool error; returns its code.
    pub async fn err(&self, tool: &str, args: Value) -> String {
        let r = self.call(tool, args).await;
        assert_eq!(r["isError"], json!(true), "{tool} should fail: {r}");
        r["structuredContent"]["error"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    pub async fn room_status(&self, room: &str) -> Option<Value> {
        let list = self.ok("room_list", json!({})).await;
        list["rooms"]
            .as_array()
            .and_then(|r| r.iter().find(|x| x["name"] == room).cloned())
    }
}
