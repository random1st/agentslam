//! Client ID Metadata Documents (CIMD): allowlist, fetch + cache, and
//! redirect URI matching (loopback redirects match on any port, RFC 8252 §7.3).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::RwLock;

use crate::core::config::Config;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientMetadata {
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CimdError {
    #[error("client is not on the allowlist")]
    NotAllowlisted,
    #[error("client metadata document could not be fetched: {0}")]
    Fetch(String),
    #[error("client metadata document is invalid: {0}")]
    Invalid(String),
}

const MAX_DOC_BYTES: usize = 64 * 1024;
/// Client metadata documents kept at once (each id is one allowlisted URL or
/// one Codex install).
const MAX_CACHE_ENTRIES: usize = 1024;

#[derive(Clone, Default)]
pub struct CimdCache {
    inner: Arc<RwLock<HashMap<String, (Instant, ClientMetadata)>>>,
}

impl CimdCache {
    /// Resolve an allowlisted client id to its metadata document. Non-allowlisted
    /// ids are refused before any network access (no SSRF via client_id).
    pub async fn resolve(
        &self,
        cfg: &Config,
        http: &reqwest::Client,
        client_id: &str,
    ) -> Result<ClientMetadata, CimdError> {
        if !cfg
            .oauth
            .allowed_clients
            .iter()
            .any(|c| client_allowed(c, client_id))
        {
            return Err(CimdError::NotAllowlisted);
        }
        let url = url::Url::parse(client_id).map_err(|e| CimdError::Invalid(e.to_string()))?;
        let scheme_ok = url.scheme() == "https"
            || (cfg.allow_insecure_http_for_tests && url.scheme() == "http");
        if !scheme_ok {
            return Err(CimdError::Invalid("client id must be an https URL".into()));
        }
        let ttl = Duration::from_secs(cfg.oauth.cimd_cache_ttl_s);
        if let Some((at, doc)) = self.inner.read().await.get(client_id)
            && at.elapsed() < ttl
        {
            return Ok(doc.clone());
        }
        let resp = http
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| CimdError::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(CimdError::Fetch(format!("HTTP {}", resp.status())));
        }
        // Read at most MAX_DOC_BYTES: stop as soon as the body grows past it
        // instead of buffering whatever the host sends.
        let mut resp = resp;
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| CimdError::Fetch(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_DOC_BYTES {
                return Err(CimdError::Invalid("document too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        let doc: ClientMetadata =
            serde_json::from_slice(&body).map_err(|e| CimdError::Invalid(e.to_string()))?;
        if doc.client_id != client_id {
            return Err(CimdError::Invalid(
                "client_id in the document does not equal its URL".into(),
            ));
        }
        if doc.redirect_uris.is_empty() {
            return Err(CimdError::Invalid("redirect_uris is empty".into()));
        }
        {
            let mut cache = self.inner.write().await;
            // Bounded: expired entries go first; past the cap the cache starts over.
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.retain(|_, (at, _)| at.elapsed() < ttl);
                if cache.len() >= MAX_CACHE_ENTRIES {
                    cache.clear();
                }
            }
            cache.insert(client_id.to_string(), (Instant::now(), doc.clone()));
        }
        Ok(doc)
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// Is `client_id` on the allowlist entry `pattern`? Exact match, or a pattern
/// whose `*` stands for exactly one non-empty path segment (Codex publishes a
/// per-install document at https://chatgpt.com/oauth/codex/<id>/client.json).
/// Scheme, host and port are compared literally; a query or fragment never matches.
pub fn client_allowed(pattern: &str, client_id: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == client_id;
    }
    let (Ok(p), Ok(c)) = (url::Url::parse(pattern), url::Url::parse(client_id)) else {
        return false;
    };
    if p.scheme() != c.scheme()
        || p.host_str() != c.host_str()
        || p.port_or_known_default() != c.port_or_known_default()
        || c.query().is_some()
        || c.fragment().is_some()
    {
        return false;
    }
    let ps: Vec<&str> = p.path().split('/').collect();
    let cs: Vec<&str> = c.path().split('/').collect();
    ps.len() == cs.len()
        && ps
            .iter()
            .zip(&cs)
            .all(|(a, b)| if *a == "*" { !b.is_empty() } else { a == b })
}

/// Does `requested` match one of the registered redirect URIs? Exact match,
/// or for http loopback redirects: same scheme, host, path and query, any port.
pub fn redirect_allowed(registered: &[String], requested: &str) -> bool {
    let Ok(req) = url::Url::parse(requested) else {
        return false;
    };
    if req.fragment().is_some() {
        return false;
    }
    registered.iter().any(|r| {
        if r == requested {
            return true;
        }
        let Ok(reg) = url::Url::parse(r) else {
            return false;
        };
        let (Some(rh), Some(qh)) = (reg.host_str(), req.host_str()) else {
            return false;
        };
        reg.scheme() == "http"
            && req.scheme() == "http"
            && is_loopback_host(rh)
            && rh == qh
            && reg.path() == req.path()
            && reg.query() == req.query()
            && req.username().is_empty()
            && req.password().is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_wildcard_matches_one_path_segment() {
        let codex = "https://chatgpt.com/oauth/codex/*/client.json";
        assert!(client_allowed(
            codex,
            "https://chatgpt.com/oauth/codex/abc123/client.json"
        ));
        assert!(!client_allowed(
            codex,
            "https://chatgpt.com/oauth/codex/a/b/client.json"
        ));
        assert!(!client_allowed(
            codex,
            "https://chatgpt.com/oauth/codex//client.json"
        ));
        assert!(!client_allowed(
            codex,
            "https://evil.example/oauth/codex/abc/client.json"
        ));
        assert!(!client_allowed(
            codex,
            "https://chatgpt.com/oauth/codex/abc/client.json?x=1"
        ));
        assert!(!client_allowed(
            codex,
            "https://chatgpt.com.evil/oauth/codex/abc/client.json"
        ));
        let exact = "https://claude.ai/oauth/claude-code-client-metadata";
        assert!(client_allowed(exact, exact));
        assert!(!client_allowed(exact, "https://claude.ai/oauth/other"));
    }

    #[test]
    fn loopback_port_agnostic() {
        let reg = vec![
            "http://localhost/callback".to_string(),
            "http://127.0.0.1/callback/abc".to_string(),
            "https://app.example.com/cb".to_string(),
        ];
        assert!(redirect_allowed(&reg, "http://localhost:53123/callback"));
        assert!(redirect_allowed(&reg, "http://127.0.0.1:1/callback/abc"));
        assert!(redirect_allowed(&reg, "https://app.example.com/cb"));
        assert!(!redirect_allowed(&reg, "https://app.example.com:8443/cb"));
        assert!(!redirect_allowed(&reg, "http://localhost:1/other"));
        assert!(!redirect_allowed(&reg, "http://evil.example.com/callback"));
        assert!(!redirect_allowed(&reg, "http://127.0.0.1:5/callback"));
    }
}
