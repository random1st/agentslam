//! Configuration: a TOML file for structure, environment variables for secrets.
//! Provider client secrets are never read from the file — only the name of
//! the env var that holds them (`client_secret_env`).

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listen address. Default 127.0.0.1:8787. A non-loopback bind requires an
    /// https `public_url` (TLS terminated in front of agentslam).
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// External base URL, e.g. `https://rooms.example.com`. It is the OAuth
    /// issuer; the MCP resource is `<public_url>/mcp`.
    pub public_url: String,
    /// SQLite file path, or `:memory:`.
    #[serde(default = "default_database")]
    pub database: String,
    /// `Secure` attribute on cookies. Turn off only for http://localhost development.
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
    /// Tests only: accept http:// (not just https://) for CIMD client
    /// metadata URLs, IdP issuers and the public URL off loopback.
    #[serde(default)]
    pub allow_insecure_http_for_tests: bool,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub oauth: OAuthConfig,
    /// Admins by upstream identity (issuer, sub).
    #[serde(default)]
    pub admins: Vec<AdminIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Google,
    Okta,
    Entra,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Stable id used in URLs (`/login/<id>`), `[a-z0-9-]+`.
    pub id: String,
    pub kind: ProviderKind,
    /// Label on the sign-in page.
    #[serde(default)]
    pub display_name: Option<String>,
    /// OIDC issuer. Defaults: google `https://accounts.google.com`, entra
    /// `https://login.microsoftonline.com/<tenant_id>/v2.0`. Required for okta.
    #[serde(default)]
    pub issuer: Option<String>,
    pub client_id: String,
    /// Name of the env var holding the client secret.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// Resolved from `client_secret_env` at load time; never deserialized.
    #[serde(skip)]
    pub client_secret: Option<String>,
    /// google: allowed values of the ID token `hd` claim.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// okta: optional group the user must be in (from `groups_claim`).
    #[serde(default)]
    pub required_group: Option<String>,
    /// entra: required `tid` claim value.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// okta/entra: claim carrying group names/ids.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// okta/entra: members of this group are admins.
    #[serde(default)]
    pub admin_group: Option<String>,
}

impl ProviderConfig {
    pub fn issuer(&self) -> String {
        match (&self.issuer, self.kind) {
            (Some(i), _) => i.trim_end_matches('/').to_string(),
            (None, ProviderKind::Google) => "https://accounts.google.com".to_string(),
            (None, ProviderKind::Entra) => format!(
                "https://login.microsoftonline.com/{}/v2.0",
                self.tenant_id.as_deref().unwrap_or_default()
            ),
            (None, ProviderKind::Okta) => String::new(),
        }
    }

    pub fn label(&self) -> String {
        self.display_name
            .clone()
            .unwrap_or_else(|| match self.kind {
                ProviderKind::Google => "Google Workspace".to_string(),
                ProviderKind::Okta => "Okta".to_string(),
                ProviderKind::Entra => "Microsoft Entra ID".to_string(),
            })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    /// Allowlisted client metadata document URLs (CIMD client ids).
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default = "default_access_ttl")]
    pub access_token_ttl_s: i64,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_s: i64,
    #[serde(default = "default_code_ttl")]
    pub code_ttl_s: i64,
    #[serde(default = "default_cimd_ttl")]
    pub cimd_cache_ttl_s: u64,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        OAuthConfig {
            allowed_clients: Vec::new(),
            access_token_ttl_s: default_access_ttl(),
            refresh_token_ttl_s: default_refresh_ttl(),
            code_ttl_s: default_code_ttl(),
            cimd_cache_ttl_s: default_cimd_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminIdentity {
    pub issuer: String,
    pub sub: String,
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8787))
}
fn default_database() -> String {
    "agentslam.db".to_string()
}
fn default_true() -> bool {
    true
}
fn default_groups_claim() -> String {
    "groups".to_string()
}
fn default_access_ttl() -> i64 {
    3600
}
fn default_refresh_ttl() -> i64 {
    30 * 86400
}
fn default_code_ttl() -> i64 {
    60
}
fn default_cimd_ttl() -> u64 {
    3600
}

pub fn valid_slug(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Config {
    /// Parse a TOML document; does not touch the environment.
    pub fn from_toml(text: &str) -> anyhow::Result<Config> {
        let cfg: Config = toml::from_str(text).context("parse config TOML")?;
        Ok(cfg)
    }

    /// Load from a file, resolve provider secrets from the environment and validate.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config file {}", path.display()))?;
        let mut cfg = Config::from_toml(&text)?;
        cfg.resolve_secrets_from_env()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn resolve_secrets_from_env(&mut self) -> anyhow::Result<()> {
        for p in &mut self.providers {
            if p.client_secret.is_some() {
                continue;
            }
            let Some(var) = &p.client_secret_env else {
                bail!(
                    "provider {}: set client_secret_env to the name of the env var holding the client secret",
                    p.id
                );
            };
            let value = std::env::var(var).with_context(|| {
                format!(
                    "provider {}: env var {var} (client_secret_env) is not set",
                    p.id
                )
            })?;
            p.client_secret = Some(value);
        }
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let public = url::Url::parse(&self.public_url).context("public_url is not a URL")?;
        ensure!(
            matches!(public.scheme(), "https" | "http"),
            "public_url must be http(s)"
        );
        if !self.bind.ip().is_loopback() {
            ensure!(
                public.scheme() == "https" || self.allow_insecure_http_for_tests,
                "bind {} is not loopback: agentslam must sit behind TLS termination, so public_url must be https",
                self.bind
            );
        }
        let mut ids = HashSet::new();
        for p in &self.providers {
            ensure!(
                valid_slug(&p.id, 1, 32),
                "provider id {:?} must match [a-z0-9-]{{1,32}}",
                p.id
            );
            ensure!(ids.insert(p.id.clone()), "duplicate provider id {}", p.id);
            ensure!(
                !p.client_id.is_empty(),
                "provider {}: client_id is empty",
                p.id
            );
            ensure!(
                p.client_secret.is_some(),
                "provider {}: client secret not resolved",
                p.id
            );
            match p.kind {
                ProviderKind::Google => ensure!(
                    !p.allowed_domains.is_empty(),
                    "provider {} (google): allowed_domains must list at least one hd value",
                    p.id
                ),
                ProviderKind::Okta => ensure!(
                    p.issuer.as_deref().is_some_and(|i| !i.is_empty()),
                    "provider {} (okta): issuer (the org issuer URL) is required",
                    p.id
                ),
                ProviderKind::Entra => ensure!(
                    p.tenant_id.as_deref().is_some_and(|t| !t.is_empty()),
                    "provider {} (entra): tenant_id is required",
                    p.id
                ),
            }
            let issuer = url::Url::parse(&p.issuer())
                .with_context(|| format!("provider {}: issuer is not a URL", p.id))?;
            ensure!(
                issuer.scheme() == "https" || self.allow_insecure_http_for_tests,
                "provider {}: issuer must be https",
                p.id
            );
        }
        for c in &self.oauth.allowed_clients {
            let u =
                url::Url::parse(c).with_context(|| format!("allowed client {c:?} is not a URL"))?;
            ensure!(
                u.scheme() == "https"
                    || (self.allow_insecure_http_for_tests && u.scheme() == "http"),
                "allowed client {c}: client metadata URLs must be https"
            );
        }
        ensure!(
            self.oauth.code_ttl_s > 0 && self.oauth.code_ttl_s <= 600,
            "oauth.code_ttl_s must be 1..600"
        );
        Ok(())
    }

    /// OAuth issuer = public URL without trailing slash.
    pub fn issuer(&self) -> String {
        self.public_url.trim_end_matches('/').to_string()
    }

    /// The protected resource (RFC 8707 audience) for MCP.
    pub fn mcp_resource(&self) -> String {
        format!("{}/mcp", self.issuer())
    }

    pub fn provider(&self, id: &str) -> Option<&ProviderConfig> {
        self.providers.iter().find(|p| p.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_provider_kind_fails() {
        let err = Config::from_toml(
            "public_url='http://127.0.0.1:1'\n[[providers]]\nid='x'\nkind='github'\nclient_id='c'\n",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("unknown variant"));
    }

    #[test]
    fn non_https_cimd_rejected_in_production() {
        let cfg = Config::from_toml(
            "public_url='http://127.0.0.1:1'\n[oauth]\nallowed_clients=['http://127.0.0.1:9/c.json']\n",
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn non_loopback_bind_requires_https() {
        let cfg = Config::from_toml("bind='0.0.0.0:8787'\npublic_url='http://rooms.example.com'\n")
            .unwrap();
        assert!(cfg.validate().is_err());
        let cfg =
            Config::from_toml("bind='0.0.0.0:8787'\npublic_url='https://rooms.example.com'\n")
                .unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn defaults_bind_loopback_and_secure_cookies() {
        let cfg = Config::from_toml("public_url='http://127.0.0.1:8787'\n").unwrap();
        assert!(cfg.bind.ip().is_loopback());
        assert!(cfg.secure_cookies);
    }
}
