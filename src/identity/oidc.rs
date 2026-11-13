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

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::core::config::{ProviderConfig, ProviderKind};
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
    /// Google account whose `hd` is missing or not allowlisted.
    #[error("your account's domain is not allowed to sign in here")]
    DomainNotAllowed,
    /// Okta group / Entra tenant check failed.
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("sign-in with the identity provider failed: {0}")]
    Upstream(String),
}

#[derive(Clone, Default)]
pub struct Oidc {
    cache: Arc<RwLock<HashMap<String, (Discovery, JwkSet)>>>,
}

impl Oidc {
    async fn load(
        &self,
        http: &reqwest::Client,
        provider: &ProviderConfig,
        force: bool,
    ) -> Result<(Discovery, JwkSet), LoginError> {
        if !force && let Some(v) = self.cache.read().await.get(&provider.id) {
            return Ok(v.clone());
        }
        let issuer = provider.issuer();
        let disc: Discovery = http
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| LoginError::Upstream(format!("discovery: {e}")))?
            .json()
            .await
            .map_err(|e| LoginError::Upstream(format!("discovery: {e}")))?;
        if disc.issuer.trim_end_matches('/') != issuer {
            return Err(LoginError::Upstream(format!(
                "discovery issuer {} does not equal configured issuer {issuer}",
                disc.issuer
            )));
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
        self.cache
            .write()
            .await
            .insert(provider.id.clone(), (disc.clone(), jwks.clone()));
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
        let group_admin = check_company(provider, &claims)?;
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| LoginError::Upstream("ID token has no sub".into()))?;
        Ok(VerifiedLogin {
            issuer: provider.issuer(),
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
        let (_, mut jwks) = self.load(http, provider, false).await?;
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

/// Provider-kind company check on verified claims. Returns whether the
/// identity is an admin through the provider's admin group.
pub fn check_company(provider: &ProviderConfig, claims: &Value) -> Result<bool, LoginError> {
    match provider.kind {
        ProviderKind::Google => {
            let hd = claims.get("hd").and_then(Value::as_str).unwrap_or("");
            let ok = !hd.is_empty()
                && provider
                    .allowed_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(hd));
            if !ok {
                return Err(LoginError::DomainNotAllowed);
            }
            Ok(false)
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
            Ok(provider.admin_group.as_ref().is_some_and(|a| g.contains(a)))
        }
        ProviderKind::Entra => {
            let tid = claims.get("tid").and_then(Value::as_str).unwrap_or("");
            if Some(tid) != provider.tenant_id.as_deref() || tid.is_empty() {
                return Err(LoginError::AccessDenied(
                    "your Microsoft account belongs to a different organization".into(),
                ));
            }
            let g = groups(claims, &provider.groups_claim);
            Ok(provider.admin_group.as_ref().is_some_and(|a| g.contains(a)))
        }
    }
}
