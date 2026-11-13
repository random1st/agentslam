//! Upstream OIDC sign-in (Google Workspace, Okta, Microsoft Entra ID).
//!
//! Choice: `jsonwebtoken` + manual discovery/JWKS rather than `openidconnect`.
//! We need exactly: discovery doc, authorize URL, code exchange, ID token
//! signature/iss/aud/exp/nonce checks, plus provider-specific company claims
//! (`hd`, `groups`, `tid`) read from raw claims. That is ~200 lines here,
//! while `openidconnect`'s typed claim model makes custom claims and the
//! Google `iss` variant awkward.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::core::config::{ProviderConfig, ProviderKind};
use crate::identity::orgs::OrgKey;
use crate::identity::people::VerifiedLogin;

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// Google account whose `hd` is not allowlisted (provider or instance).
    #[error("your account's domain is not allowed to sign in here")]
    DomainNotAllowed,
    /// Google account without `hd`: a personal account, not a company one.
    #[error("a company account is needed")]
    NoCompanyAccount,
    /// Okta group / Entra tenant / OIDC org claim check failed.
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("sign-in with the identity provider failed: {0}")]
    Upstream(String),
}

/// Discovery and JWKS are re-fetched after this long, so a key the provider
/// retired stops being trusted even when its kid is still known.
const KEYS_TTL: Duration = Duration::from_secs(3600);

/// When discovery and keys were fetched, and what they were.
type CachedKeys = (Instant, Discovery, JwkSet);

#[derive(Clone, Default)]
pub struct Oidc {
    cache: Arc<RwLock<HashMap<String, CachedKeys>>>,
    /// Tests only (`allow_insecure_http_for_tests`): skip the SSRF guard for
    /// issuers that organization admins type in, so a local mock IdP works.
    allow_private_hosts: bool,
}

/// SSRF guard for an issuer an organization admin typed in (an Okta
/// connection): https, a DNS name rather than an IP literal, and every address
/// it resolves to is public. DNS can still change between this check and the
/// fetch; redirects are off on the shared client, which limits the rest.
pub async fn check_public_https(url: &url::Url) -> Result<(), String> {
    if url.scheme() != "https" {
        return Err("must start with https://".into());
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(_) => return Err("must be a DNS name, not an IP address".into()),
        None => return Err("has no host".into()),
    };
    let internal = !host.contains('.')
        || [".local", ".internal", ".localhost", ".lan", ".home.arpa"]
            .iter()
            .any(|s| host.ends_with(s));
    if internal {
        return Err("must be a public host name".into());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| "cannot be resolved".to_string())?
        .collect();
    if addrs.is_empty() {
        return Err("cannot be resolved".into());
    }
    if addrs.iter().any(|a| !is_public_ip(a.ip())) {
        return Err("resolves to a private address".into());
    }
    Ok(())
}

fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.is_documentation()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(m));
            }
            let s0 = v.segments()[0];
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s0 & 0xfe00) == 0xfc00
                || (s0 & 0xffc0) == 0xfe80)
        }
    }
}

/// Every endpoint of an admin-typed issuer's discovery document must stay on
/// the issuer's own origin (Okta publishes them there), so the document cannot
/// point the server at another host.
fn same_origin(issuer: &str, endpoint: &str) -> bool {
    match (url::Url::parse(issuer), url::Url::parse(endpoint)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

impl Oidc {
    pub fn new(allow_private_hosts: bool) -> Self {
        Oidc {
            allow_private_hosts,
            ..Oidc::default()
        }
    }

    async fn load(
        &self,
        http: &reqwest::Client,
        provider: &ProviderConfig,
        force: bool,
    ) -> Result<(Discovery, JwkSet), LoginError> {
        if !force
            && let Some((at, d, k)) = self.cache.read().await.get(&provider.id)
            && at.elapsed() < KEYS_TTL
        {
            return Ok((d.clone(), k.clone()));
        }
        let issuer = provider.issuer();
        let guarded = provider.id.starts_with("okta-conn-") && !self.allow_private_hosts;
        if guarded {
            let url = url::Url::parse(&issuer).map_err(|e| LoginError::Upstream(e.to_string()))?;
            check_public_https(&url)
                .await
                .map_err(|e| LoginError::Upstream(format!("issuer {e}")))?;
        }
        let disc: Discovery = http
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| LoginError::Upstream(format!("discovery: {e}")))?
            .json()
            .await
            .map_err(|e| LoginError::Upstream(format!("discovery: {e}")))?;
        // Multi-tenant Entra discovery publishes a templated issuer
        // (".../{tenantid}/v2.0"); the token issuer is then checked per tid.
        let templated = provider.multi_tenant() && disc.issuer.contains("{tenantid}");
        if !templated && disc.issuer.trim_end_matches('/') != issuer {
            return Err(LoginError::Upstream(format!(
                "discovery issuer {} does not equal configured issuer {issuer}",
                disc.issuer
            )));
        }
        if guarded
            && ![
                &disc.authorization_endpoint,
                &disc.token_endpoint,
                &disc.jwks_uri,
            ]
            .iter()
            .all(|e| same_origin(&issuer, e))
        {
            return Err(LoginError::Upstream(
                "discovery endpoints must be on the issuer's own host".into(),
            ));
        }
        let jwks: JwkSet = http
            .get(&disc.jwks_uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| LoginError::Upstream(format!("jwks: {e}")))?
            .json()
            .await
            .map_err(|e| LoginError::Upstream(format!("jwks: {e}")))?;
        self.cache.write().await.insert(
            provider.id.clone(),
            (Instant::now(), disc.clone(), jwks.clone()),
        );
        Ok((disc, jwks))
    }

    pub async fn authorize_url(
        &self,
        http: &reqwest::Client,
        provider: &ProviderConfig,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        pkce_challenge: &str,
    ) -> Result<String, LoginError> {
        let (disc, _) = self.load(http, provider, false).await?;
        let mut url = url::Url::parse(&disc.authorization_endpoint)
            .map_err(|e| LoginError::Upstream(e.to_string()))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &provider.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", "openid email profile")
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", pkce_challenge)
                .append_pair("code_challenge_method", "S256");
            if provider.kind == ProviderKind::Google && provider.allowed_domains.len() == 1 {
                // Account-chooser hint only; the real check is the `hd` claim.
                q.append_pair("hd", &provider.allowed_domains[0]);
            }
        }
        Ok(url.to_string())
    }

    /// Exchange the upstream code, verify the ID token and run the company check.
    pub async fn finish(
        &self,
        http: &reqwest::Client,
        provider: &ProviderConfig,
        redirect_uri: &str,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedLogin, LoginError> {
        let (disc, _) = self.load(http, provider, false).await?;
        let secret = provider.client_secret.clone().unwrap_or_default();
        let resp = http
            .post(&disc.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", provider.client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| LoginError::Upstream(format!("token: {e}")))?;
        if !resp.status().is_success() {
            return Err(LoginError::Upstream(format!(
                "token endpoint returned HTTP {}",
                resp.status()
            )));
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| LoginError::Upstream(format!("token: {e}")))?;
        let id_token = body
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| LoginError::Upstream("no id_token in token response".into()))?;
        let claims = self
            .verify_id_token(http, provider, id_token, nonce)
            .await?;
        let (group_admin, org) = check_company(provider, &claims)?;
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| LoginError::Upstream("ID token has no sub".into()))?;
        // Multi-tenant: key identities by the per-tenant issuer from the token.
        let issuer = if provider.multi_tenant() {
            claims
                .get("iss")
                .and_then(Value::as_str)
                .map(|s| s.trim_end_matches('/').to_string())
                .unwrap_or_else(|| provider.issuer())
        } else {
            provider.issuer()
        };
        Ok(VerifiedLogin {
            issuer,
            sub: sub.to_string(),
            provider_id: provider.id.clone(),
            email: claims
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_string),
            name: claims
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string),
            group_admin,
            org,
        })
    }

    async fn verify_id_token(
        &self,
        http: &reqwest::Client,
        provider: &ProviderConfig,
        id_token: &str,
        nonce: &str,
    ) -> Result<Value, LoginError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| LoginError::Upstream(format!("ID token header: {e}")))?;
        let allowed = [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::ES256,
        ];
        if !allowed.contains(&header.alg) {
            return Err(LoginError::Upstream(
                "ID token algorithm not allowed".into(),
            ));
        }
        let kid = header.kid.clone().unwrap_or_default();
        let (disc, mut jwks) = self.load(http, provider, false).await?;
        if jwks.find(&kid).is_none() {
            // Key rotation: refetch once.
            jwks = self.load(http, provider, true).await?.1;
        }
        let jwk = jwks
            .find(&kid)
            .ok_or_else(|| LoginError::Upstream("ID token signed with an unknown key".into()))?;
        let key =
            DecodingKey::from_jwk(jwk).map_err(|e| LoginError::Upstream(format!("JWK: {e}")))?;
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[provider.client_id.as_str()]);
        let issuer = provider.issuer();
        let mut issuers = vec![issuer.clone()];
        if provider.kind == ProviderKind::Google && issuer == "https://accounts.google.com" {
            issuers.push("accounts.google.com".to_string());
        }
        if provider.multi_tenant() && disc.issuer.contains("{tenantid}") {
            // Expected issuer = https://login.microsoftonline.com/{tid}/v2.0 for
            // the token's own tid (signature still verified below).
            let tid = unverified_claim(id_token, "tid").ok_or_else(|| {
                LoginError::AccessDenied("your Microsoft account has no tenant".into())
            })?;
            if !tid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(LoginError::Upstream("ID token tid is malformed".into()));
            }
            issuers = vec![disc.issuer.replace("{tenantid}", &tid)];
        }
        validation.set_issuer(&issuers);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = jsonwebtoken::decode::<Value>(id_token, &key, &validation)
            .map_err(|e| LoginError::Upstream(format!("ID token rejected: {e}")))?;
        let claims = data.claims;
        if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
            return Err(LoginError::Upstream("ID token nonce mismatch".into()));
        }
        Ok(claims)
    }
}

fn groups(claims: &Value, claim: &str) -> Vec<String> {
    claims
        .get(claim)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Read one string claim from a JWT payload WITHOUT verifying it. Used only
/// to choose the expected issuer before the signature check.
fn unverified_claim(token: &str, claim: &str) -> Option<String> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get(claim).and_then(Value::as_str).map(str::to_string)
}

/// Provider-kind company check on verified claims (B13). Returns whether the
/// identity is an admin through the provider's admin group, and the verified
/// organization key.
pub fn check_company(
    provider: &ProviderConfig,
    claims: &Value,
) -> Result<(bool, OrgKey), LoginError> {
    let email_domain = claims
        .get("email")
        .and_then(Value::as_str)
        .and_then(|e| e.rsplit_once('@'))
        .map(|(_, d)| d.to_lowercase());
    match provider.kind {
        ProviderKind::Google => {
            let hd = claims.get("hd").and_then(Value::as_str).unwrap_or("");
            if hd.is_empty() {
                return Err(LoginError::NoCompanyAccount);
            }
            let ok = provider.allowed_domains.is_empty()
                || provider
                    .allowed_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(hd));
            if !ok {
                return Err(LoginError::DomainNotAllowed);
            }
            let hd = hd.to_lowercase();
            Ok((
                false,
                OrgKey {
                    kind: "google_hd".into(),
                    value: hd.clone(),
                    name: hd,
                },
            ))
        }
        ProviderKind::Okta => {
            let g = groups(claims, &provider.groups_claim);
            if let Some(required) = &provider.required_group
                && !g.iter().any(|x| x == required)
            {
                return Err(LoginError::AccessDenied(format!(
                    "your Okta account is not in the group \"{required}\" that this server requires"
                )));
            }
            let issuer = provider.issuer();
            Ok((
                provider.admin_group.as_ref().is_some_and(|a| g.contains(a)),
                OrgKey {
                    kind: "okta".into(),
                    name: email_domain.unwrap_or_else(|| issuer.clone()),
                    value: issuer,
                },
            ))
        }
        ProviderKind::Entra => {
            let tid = claims.get("tid").and_then(Value::as_str).unwrap_or("");
            let single = provider.tenant_id.as_deref().filter(|t| !t.is_empty());
            if tid.is_empty() || single.is_some_and(|t| t != tid) {
                return Err(LoginError::AccessDenied(
                    "your Microsoft account belongs to a different organization".into(),
                ));
            }
            let g = groups(claims, &provider.groups_claim);
            Ok((
                provider.admin_group.as_ref().is_some_and(|a| g.contains(a)),
                OrgKey {
                    kind: "entra_tid".into(),
                    value: tid.to_string(),
                    name: email_domain.unwrap_or_else(|| tid.to_string()),
                },
            ))
        }
        ProviderKind::Oidc => {
            // A fixed organization: everyone signing in through this provider
            // belongs to it, keyed by (issuer, name); no claim is read.
            if let Some(name) = provider.organization.as_deref().map(str::trim) {
                return Ok((
                    false,
                    OrgKey {
                        kind: "oidc".into(),
                        value: format!("{}#{name}", provider.issuer()),
                        name: name.to_string(),
                    },
                ));
            }
            let claim = provider.org_claim.as_deref().unwrap_or("org_id");
            let value = match claims.get(claim) {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => {
                    return Err(LoginError::AccessDenied(
                        "your account does not say which organization it belongs to".into(),
                    ));
                }
            };
            let mapped = provider.org_map.get(&value).cloned().unwrap_or(value);
            Ok((
                false,
                OrgKey {
                    kind: "oidc".into(),
                    value: format!("{}#{mapped}", provider.issuer()),
                    name: mapped,
                },
            ))
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[test]
    fn private_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                !is_public_ip(ip.parse().unwrap()),
                "{ip} must not count as public"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[test]
    fn endpoints_must_share_the_issuer_origin() {
        let iss = "https://acme.okta.com";
        assert!(same_origin(iss, "https://acme.okta.com/oauth2/v1/token"));
        assert!(!same_origin(iss, "https://169.254.169.254/latest"));
        assert!(!same_origin(iss, "http://acme.okta.com/keys"));
        assert!(!same_origin(iss, "https://acme.okta.com:8443/keys"));
    }

    #[tokio::test]
    async fn typed_issuer_must_be_a_public_https_name() {
        for u in [
            "http://acme.okta.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://agentslam.agentslam.svc.cluster.local",
            "https://metadata",
        ] {
            let url = url::Url::parse(u).unwrap();
            assert!(
                check_public_https(&url).await.is_err(),
                "{u} must be refused"
            );
        }
    }
}
