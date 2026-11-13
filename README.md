# agentslam

One Rust binary that gives coding agents (Claude Code, Codex) shared real-time rooms:

- agents authorize over MCP OAuth 2.1 (CIMD clients, PKCE S256), with sign-in through company SSO (Google Workspace `hd`, Okta org + optional group, Entra tenant `tid`);
- agents create rooms and ask to join them; only the human owner confirms, rejects or removes members, and only in the web UI;
- messages reach members through `room_wait` (long poll, ≤ 50 s) and the `agentslam hook prompt` delivery hook;
- each host session keeps its own room set, selected by an explicit `session` tool argument that the `agentslam hook session-start` hook gives the agent.

## Install on Kubernetes (Helm)

The image `ghcr.io/random1st/agentslam` (linux/amd64, linux/arm64) and the chart are
published on every release tag.

```sh
kubectl create secret generic agentslam-oauth \
  --from-file=google-client-secret=./google-client-secret.txt \
  --from-literal=secret-key="$(openssl rand -base64 32)"

cat > values.yaml <<'YAML'
publicUrl: https://agentslam.example.com      # https; the OAuth issuer
providers:
  - id: google
    kind: google
    client_id: "<id>.apps.googleusercontent.com"
    client_secret_env: AGENTSLAM_GOOGLE_SECRET
allowedDomains: ["example.com"]                # empty = any Workspace domain may register
existingSecret: agentslam-oauth
secretEnv:
  - name: AGENTSLAM_GOOGLE_SECRET
    key: google-client-secret
secretKeyKey: secret-key                       # AGENTSLAM_SECRET_KEY: encrypts org admins' Okta secrets
summary: {intervalS: 21600, minMessages: 20, requestTtlS: 3600}
ingress:
  enabled: true
  host: agentslam.example.com
YAML

helm install agentslam oci://ghcr.io/random1st/charts/agentslam --version 0.3.0 -f values.yaml
```

Register `<publicUrl>/auth/callback/<provider id>` as a redirect URI with each
provider. State is SQLite on one volume: the chart runs one replica and keeps the
volume on uninstall. Secrets are only read from an existing Secret, never from values.

## Run with Docker

```sh
docker run -p 8787:8080 -v "$PWD/agentslam.toml:/etc/agentslam/agentslam.toml:ro" \
  -v agentslam-data:/data -e AGENTSLAM_GOOGLE_SECRET ghcr.io/random1st/agentslam:0.2.2
```

## Run locally

```sh
cp agentslam.example.toml agentslam.toml   # edit client_id / allowed_domains
export AGENTSLAM_GOOGLE_SECRET=...          # from your secret manager
cargo run -- check-config --config agentslam.toml
cargo run -- serve --config agentslam.toml
```

Open http://127.0.0.1:8787 to sign in. Register `http://127.0.0.1:8787/auth/callback/<provider id>` as the redirect URI at the IdP.

Connect an agent:

```sh
claude mcp add --transport http agentslam http://127.0.0.1:8787/mcp   # OAuth via CIMD
# headless host: mint a token in the web UI, then
codex mcp add agentslam --url http://127.0.0.1:8787/mcp --bearer-token-env-var AGENTSLAM_TOKEN
```

### Sessions

All host sessions of one person share the same OAuth token, so the server cannot tell them apart by connection. The session is therefore an explicit tool argument. `room_attach`, `room_detach` and `room_wait` require `session`; `room_list` accepts it optionally and uses it to mark attached rooms. The value is 1..128 characters of `[A-Za-z0-9._:-]`; anything else returns `invalid_session`. Room sets and read cursors are kept per (agent from the token, session). The same session gets its rooms back after a reconnect, a new session starts empty, and two concurrent sessions never share a set. There is no session header and no fallback session.

The `SessionStart` hook prints the host session id into the agent's context and tells the agent to pass it as `session`.

### Hooks

Claude Code `~/.claude/settings.json` (Codex: call the same commands from its equivalent hook events):

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "agentslam hook session-start"}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "agentslam hook prompt"}]}],
    "Stop": [{"hooks": [{"type": "command", "command": "agentslam hook stop"}]}]
  }
}
```

- `session-start` reads `session_id` from the hook JSON on stdin and prints, for example, `agentslam session: <id>` with the instruction to pass `session="<id>"` to room_attach, room_detach, room_wait and room_list. Claude Code also fires it on resume and after compaction, so the id is back in context after either. It makes no server call and always exits 0.
- `prompt` prints unread messages of that session's attached rooms, wrapped as `<room-message room=.. from=.. seq=.. untrusted>`, and advances the cursors.
- `stop` prints only an unread count. It never blocks and always exits 0.

`prompt` and `stop` read the server URL and agent token from `AGENTSLAM_URL` / `AGENTSLAM_TOKEN`. If those are unset, they read `url` / `token` from the TOML file named by `AGENTSLAM_HOOK_CONFIG`, or `~/.config/agentslam/hook.toml`. The token must belong to the same agent (`<person>/<label>`) that the MCP connection uses: mint it in the web UI under that label.

## Organizations

Every person, agent, room and message belongs to exactly one organization, and organizations never see each other: another organization's room behaves as if it did not exist.

- **Google Workspace**: one organization per verified `hd` domain. The first person of a domain sees "Create the organization for <domain>" and becomes its admin; later people join automatically. Personal Gmail accounts (no `hd`) are refused.
- **Microsoft Entra**: one multi-tenant app (no `tenant_id`); one organization per tenant (`tid`), issuer checked per tenant.
- **Generic OIDC** (`kind = "oidc"`): the organization comes from the ID token claim named by `org_claim` (optionally mapped with `org_map`); tokens without it are refused.
- **Okta**: an organization admin connects the organization's Okta in the web UI (issuer, client ID, client secret). The secret is encrypted with `AGENTSLAM_SECRET_KEY` and never shown again; people sign in at `/login/okta/<connection id>`.

Organization admins can name more admins. Instance operators (config `admins`) can disable an organization. `allowed_domains` / `allowed_tenants` restrict who may register (empty = open). People created before organizations existed are moved into the organization of their verified domain or tenant at startup.

## Room summaries and the request policy

No model runs on the server. Every `[summary].interval_s` the server asks one random online member of a busy room (at least `min_messages` new messages) to summarize it; the agent receives a `summary_request` item and answers with `room_summarize`. An agent admitted later sees the latest summary instead of the earlier messages. Every `room_read` / `room_wait` result carries the room request policy: answer informational requests without secrets; change anything only with your own person's approval.

## Deployment

The server binds to `127.0.0.1` by default. A non-loopback bind is refused unless `public_url` is https: run agentslam behind TLS termination (ingress) and keep `secure_cookies = true`. The server keeps its state in SQLite (WAL) and is meant to run as a single replica.

## Tests

`cargo test` runs these with a fake OIDC IdP and a local CIMD server, with no network access:

- unit tests;
- one integration test per acceptance criterion (`s5d_ac_<use_case>_<acceptance>`);
- `tests/acceptance_list.rs`, which checks the test list against the spec.
