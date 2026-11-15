# Agent Browser × 1Password CLI (Rust)

A small **Rust executable plugin** for [`agent-browser`](https://agent-browser.dev/plugins) implementing the official `agent-browser.plugin.v1` **`credential.read`** capability using the 1Password CLI (`op`). The AI agent never receives a generic “read my vault” tool.

> Status: starter implementation. Test with mock credentials first; **no real vault, token, or production login has been configured or validated**. This repository is not associated with or endorsed by 1Password or Vercel.

## How it works

```
Hermes sr-worker (Monster) --SSH/Tailscale--> agent-browser MCP (Mac)
                                                  |
                                                  v
                                       agent-browser auth login
                                                  |
                                       credential.resolve (stdio JSON)
                                                  |
                                       this Rust executable (Mac)
                                                  |
                               op item get ITEM_ID --vault VAULT_ID
                                                  |
                                      1Password Service Account
```

* `plugin.manifest` works without a token.
* `credential.resolve` selects a **fixed** Vault ID and Item ID based on `profileName`, checks `itemRef` and the HTTPS origin, invokes `op`, verifies the returned Item/Vault/Login/website metadata, then responds with `username`, `password`, and `url`.
* 1Password Service Account Token goes only into the `op` process **environment**, not its CLI arguments, an Agent Browser config, or a Git repository.
* In the official protocol, the **plugin response itself contains the login credential**. Agent Browser consumes it locally; do not print or forward raw protocol messages through an AI tool or logging proxy.
* This version does **not** support OTP, passkeys, or credit cards. It does not auto-submit payment forms.

## Prerequisites (Mac)

- `agent-browser` 0.43.0+ (installed separately)
- Rust toolchain (for local build), or a trusted prebuilt macOS binary
- [1Password CLI](https://1password.com/downloads/command-line/) `op` installed on the **Mac running Agent Browser**
- A **dedicated, read-only** 1Password Service Account authorized to one automation vault containing only the intended test Login Item(s)
- A Login Item with a configured website URL matching the intended login origin

**Service account authentication is not a “Vault token”.** `OP_SERVICE_ACCOUNT_TOKEN` grants the service account access to explicitly authorized vaults. Each `op item get` also supplies `--vault`. The token should be provisioned on the Mac, not on Monster. For 1Password Connect Server, use a different implementation (`OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`) after separate compatibility testing.

## Build

```sh
cargo build --release
install -m 700 target/release/agent-browser-plugin-1password "$HOME/.local/bin/agent-browser-plugin-1password"
```

For macOS paths without `~/.local/bin`, create the directory first. Avoid using a public CI job with real secret values.

## Create a private local mapping (never commit it)

```sh
mkdir -p "$HOME/.config/agent-browser-plugin-1password"
cp examples/config.example.json "$HOME/.config/agent-browser-plugin-1password/config.json"
chmod 600 "$HOME/.config/agent-browser-plugin-1password/config.json"
```

Edit that local file. Set `profiles.<agent-browser-auth-profile>.vault` to the real **Vault ID**, `item` to the exact **Item ID**, and `login_url` to the expected **HTTPS login URL**. `item_ref` is an optional, non-secret alias for CLI `--item`; it never overrides the fixed ID. The item must have a website URL with the same origin and must be a `LOGIN` item.

```json
{
  "profiles": {
    "staging-example": {
      "vault": "YOUR_DEDICATED_VAULT_ID",
      "item": "YOUR_LOGIN_ITEM_ID",
      "item_ref": "Staging Example",
      "login_url": "https://example.com/login"
    }
  },
  "keychain": {
    "service": "agent-browser-1password",
    "account": "service-account"
  }
}
```

Only the `profiles` mapping is mandatory; the optional `keychain` block enables macOS Keychain fallback described below.

## Service Account Token without placing it on Monster

Choose **one** local Mac authorization method:

1. **Recommended for a macOS SSH-hosted plugin:** store the Service Account Token in the logged-in Mac user's **login Keychain** as a Generic Password entry. Configure its *service* and *account* in the mapping; this plugin uses `/usr/bin/security find-generic-password -s SERVICE -a ACCOUNT -w` to retrieve it locally. Provision through trusted macOS Keychain Access, not through an AI request or command containing the secret. A locked Keychain or access-control prompt may block noninteractive SSH; confirm separately before turning on unattended jobs.
2. **For interactive/local testing only:** supply `OP_SERVICE_ACCOUNT_TOKEN` through a trusted local secret manager in the plugin process environment. Never save it in shell history, plugin args, config JSON, process command lines, or GitHub Actions secrets for a public fork.

`AB_OP_BINARY` can point to the Mac's `op` binary, e.g. `/opt/homebrew/bin/op` if installed; `AB_OP_CONFIG` overrides the default config path. The token is passed as an environment variable **only to the child `op` process**. No `op signin` or account-wide enumeration is performed.

## Register the Rust binary with Agent Browser

Because the current upstream `plugin add owner/repo` installer uses **`npx`**, it cannot install a standalone Rust repository directly. **Register the executable manually** in `~/.agent-browser/config.json` (merge with your existing settings; do not replace the entire file):

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

Test manifest and discovery (does not read secrets):

```sh
printf '%s\n' '{"protocol":"agent-browser.plugin.v1","type":"plugin.manifest","capability":"plugin.manifest","request":{}}' | "$HOME/.local/bin/agent-browser-plugin-1password"
agent-browser plugin list
agent-browser plugin show 1password
```

Run from a trusted local Mac terminal once token permissions and profile mapping are configured:

```sh
agent-browser auth login staging-example \
  --credential-provider 1password \
  --item "Staging Example"
```

The login request uses a profile name and fixed alias; no token or password is supplied to the AI agent or process command arguments. For an existing browser login page, Agent Browser supports `--no-navigate --url https://example.com/login`, which checks the active page's origin.

## Hermes MCP nuance

Existing `sr-worker` starts Agent Browser via Tailscale SSH and has verified `open`/`get_title`. The upstream **MCP `agent_browser_auth_login` arguments currently do not expose the CLI `--credential-provider` and `--item` switches**. This Rust plugin alone does not add an MCP login tool. To make Hermes perform automated vault-backed login, first add those arguments upstream (or create a narrowly scoped local wrapper that does not expose `op` itself), then include the safe tool in `sr-worker`'s MCP allowlist.

Do **not** give Hermes an unrestricted `op` shell tool or generic plugin runner. The fixed mapping, approved origin, read-only vault, and disabled parallel browser calls should remain in place.

## Security properties and limitations

- No arbitrary vault/item discovery. No 1Password CLI interactive sign-in. No non-HTTPS origins. Item ID, Vault ID and Login category must match the static configuration; the 1Password item itself must contain a matching website origin.
- Config file is owner-readable only (`chmod 600` on Unix). Errors are generic and never echo 1Password CLI output, secrets, or CLI arguments.
- No OTP retrieval, payment authorization, or card-number handling.
- The Rust child `op` process receives the Service Account Token in its environment; privileged processes on the Mac may still inspect it. Restrict Mac shell/SSH access and run under a dedicated OS user if possible.
- Never run `agent-browser plugin run` to print credential responses. `credential.read` is designed for `auth login` only.
- Browser pages are untrusted; restrict allowed domains, and keep screenshot, DOM-value reading, network dumps, and JS evaluation away from the login step.
- macOS Keychain authorization under SSH must be tested independently. Keychain fallback is disabled if no `keychain` block is provided.
- Service Account rate limits, expiry, scoped vault permissions, and macOS sleep/network availability must be accounted for.

## Tests

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Tests use fake in-memory login data and a local fake `op` shell script only, **never** a real service-account token or Vault. The plugin protocol fixture proves manifest, approved credential resolution, denied cross-origin, and denied arbitrary Item IDs.

## License

MIT. Not an official 1Password or Agent Browser plugin.