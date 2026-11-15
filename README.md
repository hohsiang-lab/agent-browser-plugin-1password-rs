# Agent Browser × 1Password CLI (Rust)

An unofficial open-source Rust [Agent Browser](https://agent-browser.dev/plugins) **credential.read** provider using the 1Password CLI (`op`). It follows the **Hermes `browser_vault` 1Password login-backend** pattern: discover Login-item metadata, match an exact saved website origin, then read **one** selected Login item on demand.

> Status: tested with mock `op` data and CI only. It is not affiliated with 1Password, Agent Browser, or Hermes. **Do not use a personal or production vault until reviewed on your own device.**

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

The provider exposes no secret-search or item-list tool to the model. The 1Password CLI produces all metadata locally. The plugin returns credential values **only to Agent Browser's local `credential.resolve` protocol**, which itself contains the password. Do not expose raw plugin stdout, `op`, or `credential.resolve` as generic MCP tools.

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

## Connect to Agent Browser

Add this plugin entry to the existing `~/.agent-browser/config.json` on the Mac (merge; don't overwrite other settings):

```json
{
  "plugins": [
    {
      "name": "1password",
      "command": "/Users/YOU/.local/bin/agent-browser-plugin-1password",
      "args": [],
      "capabilities": ["credential.read"]
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

**There is no interactive account picker in `credential.read`.** The provider deliberately refuses ambiguous matches rather than guessing. Use your trusted local 1Password CLI/UI to determine the Item ID; do not paste Vault listings or secrets into chat.

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

Hermes currently reaches the Mac's Agent Browser MCP over Tailscale SSH. That transport can remain unchanged. **However, the currently exposed `agent_browser_auth_login` MCP tool does not pass through the CLI `--credential-provider`, `--item` and `--url` options.** This provider alone does not enable Hermes to call it. Extend those upstream MCP parameters or build a narrowly scoped audited wrapper before enabling any real login. Don't give Hermes arbitrary access to the `op` CLI.

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
