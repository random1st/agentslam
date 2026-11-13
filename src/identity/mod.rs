pub mod auth;
pub mod cimd;
pub mod oauth;
pub mod oidc;
pub mod people;
pub mod session;
pub mod tokens;

/// The authenticated agent behind an MCP or hook request. Built only from the
/// bearer token, never from request arguments.
#[derive(Debug, Clone)]
pub struct Caller {
    pub agent_id: i64,
    pub person_id: i64,
    pub handle: String,
    pub label: String,
    pub token_hash: String,
}

impl Caller {
    /// `<person>/<agent>`
    pub fn display(&self) -> String {
        format!("{}/{}", self.handle, self.label)
    }
}

pub use oauth::routes;
