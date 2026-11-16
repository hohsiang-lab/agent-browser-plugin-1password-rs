# Agent Browser × 1Password CLI (Rust)

An unofficial open-source Rust [Agent Browser](https://agent-browser.dev/plugins) **credential.read** provider using the 1Password CLI (`op`). It follows the **Hermes `browser_vault` 1Password login-backend** pattern: discover Login-item metadata, match an exact saved website origin, then read **one** selected Login item on demand.

> Status: mock-`op` CI on Ubuntu/macOS and 2026-11-16 real Mac M1 + connected ChatGPT MCP staging **QA Manager 10 Dashboard login** verified. Separate staged TOTP is not supported by Agent Browser 0.43.0. This project is not affiliated with 1Password, Agent Browser, or Hermes. **Do not use a personal or production vault until reviewed on your own device.**

## How it works

```text
Agent Browser auth login --credential-provider 1password --url https://example.com/login
       ↓ credential.resolve (local stdio; password is never sent to the AI)
Rust provider
       ├─ validate explicit HTTPS URL and optional local origin allowlist
       ├─ op item list --categories Login --format json
       ├─ match exact Origin against the item's saved website URLs
       ├─ if more than one match: require --item <exact ID or title>
       ├─ op item get ITEM_ID --vault VAULT_ID --format json
       ├─ revalidate Login category, Item ID, Vault ID and websites
       └─ op item get ITEM_ID --vault VAULT_ID --otp (optional TOTP)
       ↓
Agent Browser receives username/password/[otp] and fills the page
```

The provider exposes **no AI-facing secret-value read, raw `op` access, or generic credential resolution**. Its separate, explicitly registered `vault.list` and `vault.items.list` capabilities intentionally expose **metadata only** (see below). Login credential values travel **only through Agent Browser's local `credential.resolve` protocol**, which itself contains the password. Never expose raw plugin stdout, arbitrary `op item get`, or `credential.resolve` as a generic MCP tool.

### Why there is no Vault/Item config

Like Hermes' `OnePasswordLoginBackend`, this provider uses `op item list` to discover the Vault ID, Item ID and saved websites dynamically. You do **not** need a separate `profiles` mapping, JSON file, or per-site username/password reference. The 1Password **Service Account permissions** control which Vaults it can enumerate.

A login is eligible only if its saved website origin **exactly** matches the explicitly supplied HTTPS login URL (scheme, host and effective port). If more than one Login item matches, `--item` must specify one exact Item ID (also accepts `op:ITEM_ID`) or an unambiguous exact title. A missing URL, unknown item, duplicate title, URL mismatch or changed metadata fails closed. For high-risk deployments, also set `AB_OP_ALLOWED_ORIGINS` locally.

## Requirements

- Agent Browser with `credential.read` plugin support (currently developed against 0.43.0+)
- A local 1Password CLI (`op`) on the **same machine as Agent Browser**
- Authentication already set up for `op`: preferably a narrowly scoped read-only 1Password Service Account through `OP_SERVICE_ACCOUNT_TOKEN`, or an existing 1Password CLI session. 1Password Connect credentials (`OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`) are also recognized.
- A Login item containing a website URL. The plugin only handles Login items (not credit cards, passkeys or address entries).

`OP_SERVICE_ACCOUNT_TOKEN` is **not** a per-Vault token: its Service Account is given permissions to particular Vaults in 1Password. Store the token only on the host running the plugin; never in GitHub or in a prompt. No `hermes secrets onepassword setup` is required on the Mac; that setup controls a different Hermes secret-source feature on the machine where Hermes runs.

## Build

```sh
cargo build --release
mkdir -p "$HOME/.local/bin"
install -m 700 target/release/agent-browser-plugin-1password "$HOME/.local/bin/"
```

CI also builds a macOS ARM64 binary (`aarch64-apple-darwin`). Download only from a workflow run of a reviewed commit, and verify provenance. A CI artifact is not a signed release. Install `op` separately.

### Mac M1 install using the pinned GitHub Actions artifact

The repository includes `scripts/install-macos-arm64.sh`. It requires an authenticated GitHub CLI (`gh`), takes the **successful workflow run ID and that run's exact 40-character head commit SHA**, verifies both, downloads the ARM64 artifact, installs to `~/.local/bin`, and checks `plugin.manifest` without reading any Vault or token:

```sh
git clone https://github.com/hohsiang-lab/agent-browser-plugin-1password-rs.git
cd agent-browser-plugin-1password-rs
git checkout feat/rust-op-credential-provider
# Replace placeholders with IDs from the successful GitHub Actions run:
sh scripts/install-macos-arm64.sh <successful-run-id> <exact-full-commit-sha>
```

If `gh` isn't installed, use `brew install gh`. The installer checks real GitHub workflow API access rather than `gh auth status`, because a valid `GITHUB_TOKEN` environment variable may coexist with an expired saved default credential. **Do not run `gh auth login` just because `gh auth status` complains about an unused saved credential**; test the requested run with `gh run view <run-id> --repo hohsiang-lab/agent-browser-plugin-1password-rs --json headSha,conclusion`. Only if that API operation fails, fix GitHub CLI authentication or an existing environment token locally. The installer does not configure Agent Browser, create a 1Password session, or read Login items. The workflow artifacts expire; for long-lived use, build from reviewed source or publish a signed release.

**Check CLI authorization without revealing data**:

```sh
if op item list --categories Login --format json >/dev/null 2>&1; then
  echo "1Password CLI authentication: PASS"
else
  echo "1Password CLI authentication unavailable in this shell"
fi
```

SSH/non-interactive `op` sessions may not share desktop application authorization. If it fails, configure a dedicated read-only 1Password Service Account locally and ensure its token reaches **the Mac Agent Browser process**, not Hermes on Monster. Do not paste the token into chat, CI or shell arguments.

### Diagnose a headless Service Account without revealing credentials

After adding `OP_SERVICE_ACCOUNT_TOKEN` to the **Mac** process environment, run this local, read-only diagnostic from a **fresh** Mac shell or SSH session (use a dedicated staging test login):

```sh
python3 scripts/diagnose-credential-provider.py \
  --url https://hoh-i-carebridge.work/login
```

It prints only stage PASS/FAIL and the **count** of Login Items whose saved website matches the exact HTTPS origin. It never prints the token, login title, username, password, item ID, Vault name, TOTP, or raw JSON. The diagnostic isolates `op` authentication to the Service Account, reads the selected test Login item to validate its schema, and invokes the local Rust Plugin without submitting the browser form. If more than one item matches, rerun with `--item "EXACT-TEST-ITEM-ID"` locally; do not share item IDs. If the diagnostic passes but an **already-running** Agent Browser MCP still fails, reconnect/restart that MCP transport so it inherits the new `OP_SERVICE_ACCOUNT_TOKEN` environment; creating a new browser session alone does not restart the MCP process.

**Security:** a token in `~/.zshenv` is inherited by every Zsh child process (including arbitrary tools in the SSH account). Prefer a dedicated read-only Automation Vault and, longer term, a dedicated MCP launch wrapper with macOS Keychain. The tool deliberately suppresses `op` stderr and parses secrets only in local process memory; only run trusted, reviewed code.

### Continue an existing second-page TOTP challenge (local only)

`auth login ... --credential-provider 1password --item "..."` fills the username/password form but does not itself finish a separate `/totp` challenge. A local operator can continue the **already-open** browser session without exposing the OTP in chat, shell history, process arguments, files, or normal command output:

```sh
zsh -c 'python3 scripts/complete-totp-local.py \\
  --url https://hoh-i-carebridge.work/login \\
  --item "HO-2576 Run3020 actual invited Staff" \\
  --session op-ho2576-staging-nov16'
```

The script verifies the chosen 1Password Login Item's exact website origin, retrieves a fresh six-digit code with `op item get --otp`, checks the current browser page is on the expected `https://.../totp` origin, and sends a one-time DOM submission via `agent-browser eval --stdin`. The TOTP is not included in command-line arguments or output. It does not modify or persist any browser auth profiles. **Only attempt the code once per run**; after it says PASS, verify the page with `get url`/snapshot. A submission PASS does not by itself prove login success. If the item has no TOTP field, stop and complete MFA manually; do not turn off MFA.

## Connect to Agent Browser

Add this plugin entry to the existing `~/.agent-browser/config.json` on the Mac (merge; don't overwrite other settings):

```json
{
  "plugins": [
    {
      "name": "1password",
      "command": "/Users/YOU/.local/bin/agent-browser-plugin-1password",
      "args": [],
      "capabilities": ["credential.read", "vault.list", "vault.items.list"]
    }
  ]
}
```

The upstream `agent-browser plugin add owner/repo` command uses npm/`npx`, so a pure Rust repository must be registered manually or bundled with a future installer.

The manifest does **not** require 1Password credentials:

```sh
printf '%s\n' '{"protocol":"agent-browser.plugin.v1","type":"plugin.manifest","capability":"plugin.manifest","request":{}}' | "$HOME/.local/bin/agent-browser-plugin-1password"
agent-browser plugin list
```

For a Login item saved for `https://example.com`:

```sh
agent-browser auth login example \
  --credential-provider 1password \
  --url https://example.com/login
```

For multiple accounts at that origin, select the exact item ID or an unambiguous title:

```sh
agent-browser auth login example \
  --credential-provider 1password \
  --item "My Testing Account" \
  --url https://example.com/login
```

**There is no interactive account picker in `credential.read`.** The provider deliberately refuses ambiguous matches rather than guessing. Use `vault.items.list` (locally or through a trusted MCP client with the debug profile) to discover the exact Item ID, then pass that ID to `--item`. Do not share Vault metadata with untrusted clients.

### AI-visible Vault and Item inventory (metadata only)

The plugin also provides two **read-only custom capabilities** compatible with upstream `agent-browser plugin run`:

- `vault.list` — list Vault IDs, names and types visible to the configured 1Password Service Account.
- `vault.items.list` — list Item IDs, titles, categories, Vault names/IDs, and normalized HTTPS website **origins**, across all accessible Vaults or with filters. This does not call `op item get`.

These are **not** part of the standard `credential.read` interface, and do **not** automatically become individually named MCP tools. Agent Browser's `agent_browser_plugin_run` MCP tool (debug profile) can invoke them. On 2026-11-16, the Mac tunnel was verified with `core,state,debug`; the connected ChatGPT MCP now exposes `agent_browser_plugin_run`. Calls to `vault.list` and `vault.items.list` **passed on real host data** (1 accessible Vault, 83 Items, 43 matching staging Login Items at verification time). These are metadata counts only, not credentials.

Register both capabilities on the existing plugin entry (preserve other config fields):

```json
{
  "name": "1password",
  "command": "/Users/YOU/.local/bin/agent-browser-plugin-1password",
  "args": [],
  "capabilities": ["credential.read", "vault.list", "vault.items.list"]
}
```

From a trusted local shell:

```sh
agent-browser plugin run 1password vault.list --payload '{"limit":50,"offset":0}'
agent-browser plugin run 1password vault.items.list --payload '{"limit":50,"offset":0}'
agent-browser plugin run 1password vault.items.list --payload '{"category":"login","origin":"https://hoh-i-carebridge.work","limit":50}'
agent-browser plugin run 1password vault.items.list --payload '{"vaultId":"VAULT_ID","query":"manager","limit":50}'
```

Accepted filters: `vaultId`, `category`, `query` (title substring), `origin` (exact HTTPS origin), `limit` (1–200), and `offset` (0–100000). Vault listing supports `query`, `limit`, and `offset`. Each response reports `total` and `nextOffset` for pagination. Omit all filters to enumerate all metadata that the 1Password CLI account can list.

The returned data is reconstructed from an explicit field allowlist: **no raw JSON, usernames, passwords, notes, credit card data, TOTP, or API key values** are returned. Website URLs are normalized to HTTPS origins and stripped of paths, queries, and fragments. Titles and Vault names are metadata and can still be sensitive; only enable inventory tools for trusted AI clients, and keep the Service Account scoped to Vaults you intend to expose. Listing does **not** grant new Vault permissions or let an AI retrieve secret field values.

**Warning about logging:** the developer-facing `plugin run` tool returns metadata to the AI/MCP caller, so avoid granting this capability to clients that should not see Vault and Item titles. Never add generic `op item get`, secret field read, or card read as an exposed plugin action.

### Upstream TOTP boundary

Agent Browser 0.43.0 accepts the optional `otp` field in `ResolvedCredential`, but its `auth login` handler does not use it for a post-password second factor. A successful `auth login` tool result is not proof that the destination Dashboard is authenticated; inspect the browser URL and page. A staged challenge proposal exists at [upstream PR #1638](https://github.com/vercel-labs/agent-browser/pull/1638), but is not merged. Do not implement an incompatible custom TOTP protocol here.

### Optional local policy

Set `AB_OP_ALLOWED_ORIGINS` on the Mac plugin's environment to a comma-separated list of **exact HTTPS origins** (no paths):

```sh
export AB_OP_ALLOWED_ORIGINS="https://example.com,https://staging.example.org"
```

When unset, any Login URL allowed by the connected 1Password account is eligible, subject to exact origin matching. A dedicated automation Vault/Service Account is strongly recommended. An explicitly empty or malformed allowlist is rejected. For background-launched Agent Browser processes on macOS, the plugin checks `/opt/homebrew/bin/op` and `/usr/local/bin/op` before falling back to `PATH`; `AB_OP_BINARY` explicitly overrides this detection. This avoids relying on the reduced `PATH` often inherited from `launchd`, but does not guarantee an authenticated 1Password session in that process.

### Authentication modes

The plugin invokes the local `op` command with a minimal subprocess environment. It chooses, in order: `OP_SERVICE_ACCOUNT_TOKEN` (scoped Service Account), paired `OP_CONNECT_HOST`/`OP_CONNECT_TOKEN`, then existing `OP_SESSION`/`OP_SESSION_*` plus `OP_ACCOUNT`. It can use `op`'s normal local CLI sign-in state. **It does not ask the AI for a password, execute `op signin`, store tokens, or read macOS Keychain itself.**

The Agent Browser upstream protocol currently limits the entire provider call to **15 seconds**, so this plugin budgets 5 seconds to list items, 5 seconds to fetch a selected item and 2 seconds to attempt TOTP. Long network/locked-session operations may fail cleanly; don't increase the timeouts beyond the upstream limit without changing Agent Browser as well.

### TOTP

The upstream `ResolvedCredential` schema includes an optional `otp` field. If a Login item supports `op item get --otp`, this plugin includes a validated 6–10-digit code in its local response. If there is no authenticator field or a TOTP fetch fails, login credentials are still returned without `otp`.

**This is not a guarantee that Agent Browser will complete a separate or delayed 2FA page automatically**. That requires a real browser E2E test and possibly upstream work. OTP is never printed to the AI.

## Hermes `sr-worker` on Monster

Hermes currently reaches the Mac's Agent Browser MCP over Tailscale SSH. That transport can remain unchanged. **Native Hermes `sr-worker` MCP parameter/allowlist parity remains unverified and is tracked in issue #2.** The advertised typed `agent_browser_auth_login` arguments still do not list `credentialProvider`, `item` and `url`, but the **connected ChatGPT Agent Browser MCP** accepted shared `extraArgs` for `--credential-provider 1password --item <exact ID> --url <staging URL>`. On 2026-11-16 a real QA Manager 10 account successfully reached the authenticated staging `/dashboard` after a `loggedIn: true` response. This proves the connected ChatGPT path, **not** native Hermes `sr-worker` parity. Do not expose arbitrary 1Password item reads or credential output in MCP. Don't give Hermes arbitrary access to the `op` CLI.

Hermes' native `browser_vault` works with browsers it owns; it does not automatically own a remote Agent Browser MCP session. This Rust project is for Agent Browser's independent credential plugin interface.

## Security boundaries

- Never place a token, password, OTP, Vault listing or other 1Password output in GitHub, CI logs, MCP tool results, shell arguments or chatbot messages.
- `op item list` metadata stays local. Only an unambiguous, exact-origin Login item can be fetched. Full Item ID/Vault ID/category/origin are **rechecked after resolution**, guarding changed metadata.
- Commands use no shell, bounded stdout, quiet stderr and subprocess timeouts. Service Account privileges should be read-only and restricted to a dedicated test Vault.
- Password and optional OTP are returned in local plugin protocol JSON, as required by Agent Browser. Pages and JavaScript running at an approved origin may still read credentials entered there. Treat browser sessions as sensitive.
- The optional `AB_OP_ALLOWED_ORIGINS` setting adds a host-local restriction but cannot replace a least-privilege Service Account.
- This plugin intentionally does not offer credit card data or automatically submit payments.

## Tests

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

The integration tests use a local fake `op` script and **fake values only**; CI needs no real Vault, Token or browser.

MIT licensed. This repository is not an official 1Password or Agent Browser integration.
