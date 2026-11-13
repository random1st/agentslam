//! agentslam: SSO-authorized MCP rooms for coding agents with owner-confirmed admission.
//!
//! Layout follows the spec's governed components:
//! - [`core`]: config, store, errors, clock, router assembly.
//! - [`identity`]: upstream OIDC sign-in, OAuth authorization server, tokens, web sessions.
//! - [`rooms`]: rooms, admission, messages, session room sets, wait/notify, MCP tools.
//! - [`web`]: web UI routes, JSON API and SSE.
//! - [`hook`]: `agentslam hook prompt|stop` client and its server endpoints.

pub mod core;
pub mod hook;
pub mod identity;
pub mod rooms;
pub mod web;
