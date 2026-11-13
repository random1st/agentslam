# agentslam — SSO for MCP connection and web UI (research, 2026-11-12)

Legend: [V] verified (URL or local command), [A] assumed / not verified.
Stage: Explore. Nothing here was built or signed into.

## 1. MCP authorization spec (draft revision; stable 2026-07-28 per Keycloak/ext-auth pages)
Source: https://modelcontextprotocol.io/specification/draft/basic/authorization (+ /client-registration)
- [V] Auth is OPTIONAL for MCP, but HTTP transports SHOULD conform.
- [V] The MCP server is an OAuth 2.1 resource server. It MUST publish Protected Resource Metadata (RFC 9728), return 401 + `WWW-Authenticate: Bearer resource_metadata=...`, validate that tokens were issued for it (audience, RFC 8707), accept only `Authorization: Bearer` (never query string), and answer 401 for invalid/expired tokens.
- [V] The authorization server (AS) MUST implement OAuth 2.1 (PKCE) and provide RFC 8414 metadata OR OIDC discovery. It SHOULD send `iss` (RFC 9207).
- [V] Clients MUST send `resource` in both authorize and token requests, use PKCE, and validate `iss`.
- [V] Registration: client priority is pre-registered, then CIMD (`client_id_metadata_document_supported`), then DCR (RFC 7591), then manual. CIMD is SHOULD for AS and clients. DCR is now MAY and DEPRECATED (kept for compatibility).
- [V] Refresh tokens: AS discretion; `offline_access` only if advertised in AS metadata.
- [V] Extensions (stable, 2026-07-28): Enterprise-Managed Authorization (IdP issues an ID-JAG, client exchanges it at the MCP AS, no per-server browser consent; Okta issues/accepts, Entra not listed) and OAuth Client Credentials. https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- Implication: SSO login with Google/Okta/Entra does NOT happen at the MCP client. The MCP AS (agentslam or a broker) must itself be an OIDC relying party of those IdPs.

## 2. Client support
Claude Code 2.1.322 (local) and Codex 0.167.2 (local).
- [V] Claude Code does the OAuth browser flow for HTTP servers (`/mcp`, and `claude mcp login <name> [--no-browser]`, local --help). Discovery via RFC 9728, then RFC 8414. DCR is the default, CIMD is auto-discovered. `claude mcp add --client-id --client-secret --callback-port` (local --help) for pre-registered clients. `oauth.authServerMetadataUrl` overrides discovery. https://code.claude.com/docs/en/mcp
- [V] Claude Code refreshes tokens on 401 using the refresh token; `offline_access` is added automatically if advertised. A stored refresh-token rejection triggers a re-auth notice.
- [V] Headless: `claude -p`/SDK cannot run the flow; sign in beforehand. `claude mcp login --no-browser` prints the URL, you paste the redirect URL back (needs an interactive TTY, `ssh -t`). Static `--header "Authorization: Bearer"` or `headersHelper` (script printing JSON headers; re-run on 401). If a configured Authorization header exists, there is NO OAuth fallback.
- [V] Codex: `codex mcp login <name> [--no-browser] [--scopes] [--oauth-client-registration auto|cimd|dcr]` (local --help). `codex mcp add --url ... --oauth-client-id/--oauth-client-secret`, `bearer_token_env_var`, `http_headers`, `env_http_headers`, `http_headers_helper`, `mcp_oauth_callback_port/url`. CIMD is auto only if the AS advertises it, `none` is in `token_endpoint_auth_methods_supported` and the callback is loopback; else DCR; a configured client_id always wins. Codex wants `authorization_response_iss_parameter_supported: true` for a stable callback. https://learn.chatgpt.com/docs/extend/mcp?surface=cli
- [V] Neither documents device flow or client-credentials for MCP. The documented headless routes are `--no-browser` paste flow, pre-issued bearer via env/header, or a headers helper.
- [A] Both clients refuse/limit non-HTTPS token endpoints off loopback (Claude Code doc states this for credentials).

## 3. Architecture options

| | (a) agentslam = own AS, federates to IdPs via OIDC | (b) broker as MCP AS (Keycloak / WorkOS AuthKit / Auth0 / Stytch) | (c) a: own AS but thin: only `openidconnect` login + minimal AS, CIMD-only + pre-issued agent tokens for headless |
|---|---|---|---|
| DCR/Google no-DCR | Irrelevant: Google/Okta/Entra are only upstream OIDC logins with ONE pre-registered agentslam client at each. agentslam serves CIMD and/or `/register` to Claude/Codex itself. | Same: broker holds upstream IdP clients and offers CIMD/DCR to MCP clients. | Same as (a), CIMD-first. |
| Ops cost | Must write authorize/token/refresh/revoke/JWKS/metadata, consent, key rotation. Code ~1-2k LOC [A]. | Keycloak: Postgres, upgrades, realm config; CIMD only experimental in 26.7 (Preview planned 26.8) and creates persistent clients. WorkOS: no infra, but $125/connection/month per enterprise SSO connection (3 IdPs ~ $375/mo) [V, secondary sources]; Google/Okta/Entra pricing check at workos.com/pricing. | Smallest. |
| Security | Highest burden: code reuse, PKCE check, redirect validation, CIMD SSRF (spec: security-considerations). rmcp example skips PKCE/secret checks (demo). | Battle-tested AS; audience binding quirks (Dex ignores RFC 8707). Immediate revocation needs token introspection or short tokens plus agentslam-side denylist. | Same as (a) but smaller surface. |
| Rust fit | `openidconnect`/`oauth2` are CLIENT-side crates [A: from knowledge; not re-verified]: good for upstream login. rmcp 3.9 has `auth` feature = client side; server example `complex_auth_streamhttp.rs` shows AS+PRM+middleware pattern in axum [V]. Server-side AS crates: unverified. | Verify JWTs with `jsonwebtoken` + JWKS; trivial. | Same as (a). |
| EKS us-west-2 | Single pod; SQLite PVC already planned; no extra service. | Keycloak = extra StatefulSet + Postgres; hosted = egress only. | Single pod. |
| Revocation (CONCEPT 5b.2) | Opaque tokens in agentslam DB: instant. | JWT: instant only if agentslam checks its own agent-status table per call (do that regardless). | Same as (a). |

Others considered: Ory Hydra OSS: DCR yes, CIMD not in OSS (Enterprise/Network only) [V search]; Dex: no CIMD, ignores RFC 8707 [V search]; Zitadel: unverified. Enterprise-Managed Authorization (ID-JAG): Okta can issue, but Google/Entra not listed [V]; Claude Code/Codex client support unverified, so not usable for v1.

## 4. Identity mapping and lifetimes
- Person = IdP `sub` + verified email (key on `(issuer, sub)`, email as label; Google says do not use email as id: https://developers.google.com/identity/openid-connect/openid-connect [V]).
- Agent name: [A recommendation] chosen at agentslam's own consent page (default from CIMD/DCR `client_name`, e.g. "Claude Code", editable, `<person>/<agent>` unique). Reason: client_name is client-controlled and not unique per person; two machines running claude-code would collide. Each completed authorization = one agent identity row; token bound to it. Re-login with the same label reuses the identity (admission survives).
- `session_key` stays separate from auth (token = agent identity; `X-Agentslam-Session` header or hook registration). Not an OAuth concept. Unverified whether either client can set it per session.
- Tokens: [A] opaque access token 1 h, refresh token 30-90 d rotating, stored hashed. Revoke = flip agent status; server checks status on every request and closes long-polls, so revocation is immediate regardless of access-token lifetime. Offboarding a person (IdP-disabled) is not seen without re-login: use refresh (re-check IdP not needed) plus an admin "disable person" action. [A] Optional: store upstream refresh token to re-validate the person; skip in v1.
- Headless Hermes hosts: [A] admin or person mints a long-lived agent token in the web UI (post-SSO) and it is passed via `--bearer-token-env-var` / `env_http_headers`; same table, same revocation. Keeps the old token design as the non-interactive fallback, now minted only by an SSO-authenticated person. Caveat [V]: Claude Code with a static Authorization header never falls back to OAuth.

## 5. Domain restriction and roles
- [V] Google: `hd` request parameter is only an account-chooser hint; verify the ID token `hd` claim server-side, plus `email_verified`; do not derive org from the email domain. Personal Gmail has no `hd`. Allowlist the company domains explicitly. https://developers.google.com/identity/openid-connect/openid-connect
- Okta/Entra: [A] restrict by tenant (single-tenant Entra app, issuer pin) and by an allowlist table `(issuer, email domain)`; Okta groups claim -> admin role needs a `groups` claim configured on the Okta app/authz server; Entra uses `groups`/app roles claim (group overage caveat above ~200 groups). Simpler v1: admin = email allowlist in config.
- Multi-IdP: a person logging in via two IdPs must map to one person: link by verified email, `(issuer,sub)` as secondary key. Account-takeover risk if an IdP does not verify email [A]; trust only configured issuers.

## 6. Recommendation
Option (a)/(c): agentslam is its own minimal OAuth AS, federating to IdPs with `openidconnect`. Reasons: the single pod, no new infra; Google/Entra no-DCR problem disappears (agentslam is the only registered client at each IdP, MCP clients see CIMD/DCR on agentslam); revocation is local and instant; WorkOS cost grows per IdP connection.
Minimal v1 cut:
1. One IdP: Google Workspace (hd check). Config-driven provider list so Okta/Entra are config entries (generic OIDC) in v1.1.
2. AS endpoints: PRM (RFC 9728), AS metadata with `client_id_metadata_document_supported` and `authorization_response_iss_parameter_supported: true`, `/authorize`, `/token` (auth code + refresh), `/register` (DCR for Claude Code default path), S256 PKCE enforced, `resource` audience check, opaque tokens hashed in SQLite.
3. Consent page: choose agent label. Web UI uses the same OIDC login with a session cookie.
4. Headless fallback: person mints an agent token in the web UI.
5. Do not build: ID-JAG, step-up scopes, client credentials, JWT access tokens.

## 7. Experiments before building (all local, no external apps)
1. Run the rmcp `complex_auth_streamhttp` example locally; `claude mcp add --transport http` then `/mcp`: confirm Claude Code completes DCR+PKCE and which redirect URI it uses. Repeat with `codex mcp login` (auto/cimd/dcr) and `--no-browser`.
2. Check whether Claude Code and Codex send CIMD `client_id` when AS advertises it, and what `client_name` is visible to the server.
3. Confirm refresh behavior: short access TTL (60 s), observe both clients refreshing; then revoke and observe the error path (401 vs 403, re-auth prompt).
4. Verify whether either client can put the session id in a header (CONCEPT 2).
5. Confirm `openidconnect` 4.x server-side suitability and whether a maintained Rust AS crate exists (not verified here).
6. Confirm headless path on a Hermes host: bearer via env var works for Codex; Claude Code `headers` with Authorization.
7. Decide the Entra path: needs a registered app at Entra anyway (no DCR/CIMD) [V search]; fine under (a).

## Sources
- https://modelcontextprotocol.io/specification/draft/basic/authorization
- https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
- https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- https://code.claude.com/docs/en/mcp
- https://learn.chatgpt.com/docs/extend/mcp?surface=cli
- https://developers.google.com/identity/openid-connect/openid-connect
- https://docs.rs/crate/rmcp/latest ; https://github.com/modelcontextprotocol/rust-sdk (examples/servers/src/complex_auth_streamhttp.rs)
- https://www.keycloak.org/securing-apps/mcp-authz-server ; https://www.keycloak.org/2026/07/keycloak-2670-released
- https://github.com/ory/hydra/issues/4061 ; https://workos.com/docs/authkit/mcp
- Local: `claude mcp add --help`, `claude mcp login --help` (2.1.322), `codex mcp login --help` (0.167.2)

## Experiment results (2026-11-12, local probe on 127.0.0.1, Claude Code 2.1.322, codex-cli 0.167.2)

Probe: logging stub AS/RS (`~/.diana-work/agentslam-probe/probe.py`, outside the repo).

- [V] Discovery, both clients: unauthenticated `/mcp` → 401 with `WWW-Authenticate: Bearer resource_metadata=…`
  → `GET /.well-known/oauth-protected-resource/mcp` → `GET /.well-known/oauth-authorization-server`.
  Claude Code sends `MCP-Protocol-Version: 2025-11-25`.
- [V] Authorize request, both: `response_type=code`, PKCE `S256`, `state`, `resource=<server>/mcp` (RFC 8707),
  loopback `redirect_uri` on a random port (Claude `http://localhost:<port>/callback`,
  Codex `http://127.0.0.1:<port>/callback/<id>`).
- [V] DCR (AS advertises `registration_endpoint`): Claude registers `client_name: "Claude Code (<server name>)"`,
  Codex `client_name: "Codex"`; both public (`token_endpoint_auth_method: none`), `application_type: native`,
  grants `authorization_code` + `refresh_token`. `client_name` carries no person/agent identity.
- [V] CIMD (AS advertises `client_id_metadata_document_supported: true`, no registration endpoint): no `/register`;
  `client_id` = vendor-hosted URL — Claude `https://claude.ai/oauth/claude-code-client-metadata`,
  Codex `https://chatgpt.com/oauth/codex/<id>/client.json`. Documents list `redirect_uris` WITHOUT a port
  (`http://localhost/callback`, `http://127.0.0.1/callback`; Codex `/callback/<id>`) → the AS must match
  loopback redirects port-agnostically (RFC 8252 §7.3).
- [V] `--no-browser` needs a TTY (Claude refuses on non-terminal stdin; `ssh -t` works per its message).
- [V] `CLAUDE_CODE_SESSION_ID` is present in the environment of processes spawned by a Claude Code session.
- [open] Session id in an MCP header via `headersHelper`: helper runs only in a trusted workspace; in the
  headless `claude -p` run it was not invoked — not verified end to end. Fallback stays: the hook (stdin carries
  `session_id`) registers the session with the server.

Consequences for the design:
1. Advertise CIMD and accept only an allowlist of client metadata URLs (Claude Code, Codex) — no open DCR in v1.
   Fetch and cache the metadata document; validate `redirect_uri` against it with loopback port-agnostic matching.
2. The agent part of `<person>/<agent>` comes from the consent page (client metadata only says "Claude Code"/"Codex").
3. Headless hosts: personal agent token minted in the web UI (no device flow in either client).
