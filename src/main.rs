//! Agent Browser credential.read provider backed by 1Password CLI ("op").
//!
//! Like Hermes browser_vault: list Login metadata first, bind the request to
//! an exact saved website origin, then resolve one item's credentials on demand.
//! No vault/item mapping or 1Password token is stored by this plugin.

use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use url::Url;

const PROTOCOL: &str = "agent-browser.plugin.v1";
const MAX_REQUEST: u64 = 65_536;
const MAX_OP_OUTPUT: usize = 1_048_576;
// Agent Browser currently gives credential plugins 15 seconds in total.
const LIST_TIMEOUT: Duration = Duration::from_secs(5);
const ITEM_TIMEOUT: Duration = Duration::from_secs(5);
const OTP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct Envelope {
    protocol: String,
    #[serde(rename = "type")]
    request_type: String,
    capability: String,
    #[serde(default)]
    request: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveRequest {
    profile_name: String,
    #[serde(default)]
    item_ref: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Clone)]
struct ItemMeta {
    id: String,
    vault_id: String,
    title: String,
}

fn main() {
    // stdout is exclusively the protocol response; never print raw op output.
    let response = execute().unwrap_or_else(|_| {
        json!({
            "protocol": PROTOCOL,
            "success": false,
            "error": "credential unavailable or request not authorized"
        })
    });
    let mut out = io::stdout().lock();
    if serde_json::to_writer(&mut out, &response).is_ok() {
        let _ = out.write_all(b"\n");
    }
}

fn execute() -> Result<Value, ()> {
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() as u64 > MAX_REQUEST {
        return Err(());
    }
    let envelope: Envelope = serde_json::from_slice(&input).map_err(|_| ())?;
    if envelope.protocol != PROTOCOL {
        return Err(());
    }
    if envelope.request_type == "plugin.manifest" && envelope.capability == "plugin.manifest" {
        return Ok(json!({
            "protocol": PROTOCOL,
            "success": true,
            "manifest": {
                "name": "1password",
                "capabilities": ["credential.read"],
                "description": "1Password CLI logins selected by exact browser origin"
            }
        }));
    }
    if envelope.request_type != "credential.resolve" || envelope.capability != "credential.read" {
        return Err(());
    }
    let request: ResolveRequest = serde_json::from_value(envelope.request).map_err(|_| ())?;
    if request.profile_name.trim().is_empty() || request.profile_name.len() > 128 {
        return Err(());
    }
    let login_url = request.url.as_deref().ok_or(())?;
    let required_origin = https_origin(login_url)?;
    ensure_allowed_origin(&required_origin)?;

    // Listing is metadata-only, not exposed to the model. All matches are
    // checked against the browser's requested origin *before* op item get.
    let list_json = op_json(
        &["item", "list", "--categories", "Login", "--format", "json"],
        LIST_TIMEOUT,
    )?;
    let matches = matching_logins(&list_json, &required_origin)?;
    let item = select_login(&matches, request.item_ref.as_deref())?;

    let item_json = op_json(
        &[
            "item",
            "get",
            &item.id,
            "--vault",
            &item.vault_id,
            "--format",
            "json",
        ],
        ITEM_TIMEOUT,
    )?;
    let (username, password) = verified_login(&item_json, item, &required_origin)?;
    let mut credential = json!({
        "username": username,
        "password": password,
        "url": login_url
    });

    // The upstream ResolvedCredential protocol accepts an optional "otp".
    // This does not guarantee every multi-page 2FA UI will auto-fill it.
    if let Some(otp) = read_otp(item) {
        credential["otp"] = json!(otp);
    }
    Ok(json!({
        "protocol": PROTOCOL,
        "success": true,
        "credential": credential
    }))
}

fn https_origin(url: &str) -> Result<String, ()> {
    let parsed = Url::parse(url).map_err(|_| ())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(());
    }
    Ok(parsed.origin().ascii_serialization())
}

fn ensure_allowed_origin(requested_origin: &str) -> Result<(), ()> {
    // Optional defense in depth for a service account with access to more
    // than one website. An explicitly empty list fails closed.
    if let Some(raw) = env::var_os("AB_OP_ALLOWED_ORIGINS") {
        let raw = raw.to_str().ok_or(())?;
        let values: Vec<_> = raw.split(',').map(str::trim).collect();
        if values.is_empty() || values.iter().any(|v| v.is_empty()) {
            return Err(());
        }
        let mut permitted = false;
        for value in values {
            let allowed = https_origin(value)?;
            // Require the allowlist to contain only origins, not arbitrary paths.
            if value != allowed {
                return Err(());
            }
            if allowed == requested_origin {
                permitted = true;
            }
        }
        if !permitted {
            return Err(());
        }
    }
    Ok(())
}

fn matching_logins(list: &Value, required_origin: &str) -> Result<Vec<ItemMeta>, ()> {
    let items = list.as_array().ok_or(())?;
    let mut matches = Vec::new();
    for entry in items {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(vault_id) = entry
            .get("vault")
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if id.is_empty() || vault_id.is_empty() {
            continue;
        }
        if !contains_origin(entry, required_origin) {
            continue;
        }
        matches.push(ItemMeta {
            id: id.to_owned(),
            vault_id: vault_id.to_owned(),
            title: entry
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        });
    }
    Ok(matches)
}

fn contains_origin(item: &Value, required_origin: &str) -> bool {
    item.get("urls")
        .and_then(Value::as_array)
        .is_some_and(|urls| {
            urls.iter()
                .filter_map(|u| u.get("href").and_then(Value::as_str))
                .any(|url| https_origin(url).ok().as_deref() == Some(required_origin))
        })
}

fn select_login<'a>(matches: &'a [ItemMeta], item_ref: Option<&str>) -> Result<&'a ItemMeta, ()> {
    let filtered: Vec<&ItemMeta> = match item_ref {
        None => matches.iter().collect(),
        Some(reference) => {
            if reference.trim().is_empty() {
                return Err(());
            }
            let id = reference.strip_prefix("op:").unwrap_or(reference);
            matches
                .iter()
                .filter(|m| m.id == id || m.title == reference)
                .collect()
        }
    };
    // Never choose the first account when a site has multiple matches.
    if filtered.len() != 1 {
        return Err(());
    }
    Ok(filtered[0])
}

fn verified_login(
    item: &Value,
    metadata: &ItemMeta,
    required_origin: &str,
) -> Result<(String, String), ()> {
    if item.get("id").and_then(Value::as_str) != Some(metadata.id.as_str())
        || item
            .get("vault")
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            != Some(metadata.vault_id.as_str())
        || !item
            .get("category")
            .and_then(Value::as_str)
            .is_some_and(|v| v.eq_ignore_ascii_case("LOGIN"))
        || !contains_origin(item, required_origin)
    {
        return Err(());
    }
    Ok((
        field(item, "USERNAME", "username")?,
        field(item, "PASSWORD", "password")?,
    ))
}

fn field(item: &Value, purpose: &str, label: &str) -> Result<String, ()> {
    let fields = item.get("fields").and_then(Value::as_array).ok_or(())?;
    let preferred: Vec<&str> = fields
        .iter()
        .filter(|f| {
            f.get("purpose")
                .and_then(Value::as_str)
                .is_some_and(|p| p.eq_ignore_ascii_case(purpose))
        })
        .filter_map(|f| f.get("value").and_then(Value::as_str))
        .collect();
    let candidates = if preferred.is_empty() {
        fields
            .iter()
            .filter(|f| {
                ["id", "label"].iter().any(|key| {
                    f.get(*key)
                        .and_then(Value::as_str)
                        .is_some_and(|v| v.eq_ignore_ascii_case(label))
                })
            })
            .filter_map(|f| f.get("value").and_then(Value::as_str))
            .collect::<Vec<_>>()
    } else {
        preferred
    };
    if candidates.len() != 1 || candidates[0].is_empty() || candidates[0].len() > 16_384 {
        return Err(());
    }
    Ok(candidates[0].to_owned())
}

fn read_otp(item: &ItemMeta) -> Option<String> {
    let output = op_output(
        &["item", "get", &item.id, "--vault", &item.vault_id, "--otp"],
        OTP_TIMEOUT,
        128,
    )
    .ok()?;
    let value = String::from_utf8(output).ok()?;
    let code = value.trim();
    (code.len() >= 6 && code.len() <= 10 && code.bytes().all(|b| b.is_ascii_digit()))
        .then(|| code.to_owned())
}

fn op_json(args: &[&str], timeout: Duration) -> Result<Value, ()> {
    let output = op_output(args, timeout, MAX_OP_OUTPUT)?;
    serde_json::from_slice(&output).map_err(|_| ())
}

fn op_output(args: &[&str], timeout: Duration, max_bytes: usize) -> Result<Vec<u8>, ()> {
    let binary = env::var_os("AB_OP_BINARY").unwrap_or_else(|| "op".into());
    if binary.is_empty() {
        return Err(());
    }
    let mut command = Command::new(binary);
    command.args(args);
    configure_op_environment(&mut command);
    run_bounded(command, max_bytes, timeout)
}

fn configure_op_environment(command: &mut Command) {
    command.env_clear();
    for key in [
        "PATH",
        "HOME",
        "USER",
        "TMPDIR",
        "TMP",
        "LANG",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "OP_CONFIG_DIR",
        "OP_LOAD_DESKTOP_APP_SETTINGS",
        "OP_BIOMETRIC_UNLOCK_ENABLED",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("NO_COLOR", "1");
    // Prefer a scoped Service Account Token, then a correctly paired Connect
    // credential, then an existing CLI session. Never combine auth modes.
    if let Some(token) = env::var_os("OP_SERVICE_ACCOUNT_TOKEN").filter(|v| !v.is_empty()) {
        command.env("OP_SERVICE_ACCOUNT_TOKEN", token);
    } else if let (Some(host), Some(token)) = (
        env::var_os("OP_CONNECT_HOST").filter(|v| !v.is_empty()),
        env::var_os("OP_CONNECT_TOKEN").filter(|v| !v.is_empty()),
    ) {
        command.env("OP_CONNECT_HOST", host);
        command.env("OP_CONNECT_TOKEN", token);
    } else {
        if let Some(account) = env::var_os("OP_ACCOUNT") {
            command.env("OP_ACCOUNT", account);
        }
        for (key, value) in env::vars_os() {
            if let Some(name) = key.to_str() {
                if name == "OP_SESSION" || name.starts_with("OP_SESSION_") {
                    command.env(key, value);
                }
            }
        }
    }
}

/// Run op directly (no shell); suppress stderr, bound stdout and kill on timeout.
/// Secrets never appear in error text or command-line arguments.
fn run_bounded(mut command: Command, max_bytes: usize, timeout: Duration) -> Result<Vec<u8>, ()> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let reader = child.stdout.take().ok_or(())?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ())
            .and(if bytes.len() > max_bytes {
                Err(())
            } else {
                Ok(bytes)
            });
        let _ = sender.send(result);
    });
    let received = receiver.recv_timeout(timeout);
    if !matches!(received, Ok(Ok(_))) {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| ())?;
    let _ = worker.join();
    if !status.success() {
        return Err(());
    }
    received.map_err(|_| ())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, title: &str) -> ItemMeta {
        ItemMeta {
            id: id.to_owned(),
            title: title.to_owned(),
            vault_id: "vault-a".into(),
        }
    }

    #[test]
    fn exact_https_origins_only() {
        assert_eq!(
            https_origin("https://EXAMPLE.com/login").unwrap(),
            "https://example.com"
        );
        for url in [
            "http://example.com",
            "https://evil.example.com",
            "https://example.com.evil.tld",
            "https://u:p@example.com/login",
        ] {
            assert_ne!(https_origin(url).ok().as_deref(), Some("https://example.com"));
        }
    }

    #[test]
    fn select_requires_disambiguation() {
        let items = [meta("a", "Team"), meta("b", "Team")];
        assert!(select_login(&items, None).is_err());
        assert!(select_login(&items, Some("Team")).is_err());
        assert_eq!(select_login(&items, Some("op:b")).unwrap().id, "b");
        assert_eq!(select_login(&items, Some("a")).unwrap().id, "a");
    }

    #[test]
    fn only_metadata_at_matching_origin() {
        let data = json!([
            {"id":"a","title":"ok","vault":{"id":"vault-a"},"urls":[{"href":"https://example.com/login"}]},
            {"id":"b","title":"evil","vault":{"id":"vault-b"},"urls":[{"href":"https://example.com.evil.tld/login"}]},
            {"id":"c","title":"sub","vault":{"id":"vault-c"},"urls":[{"href":"https://login.example.com"}]}
        ]);
        let found = matching_logins(&data, "https://example.com").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "a");
    }

    #[test]
    fn item_metadata_reverified_at_secret_resolution() {
        let meta = meta("a", "Test");
        let valid = json!({
            "id":"a", "vault":{"id":"vault-a"}, "category":"LOGIN",
            "urls":[{"href":"https://example.com/login"}],
            "fields":[
                {"purpose":"USERNAME","value":"alice@example.com"},
                {"purpose":"PASSWORD","value":"fake-secret"}
            ]
        });
        assert!(verified_login(&valid, &meta, "https://example.com").is_ok());
        let mut changed = valid.clone();
        changed["urls"][0]["href"] = json!("https://elsewhere.example/login");
        assert!(verified_login(&changed, &meta, "https://example.com").is_err());
        changed = valid.clone();
        changed["vault"]["id"] = json!("other-vault");
        assert!(verified_login(&changed, &meta, "https://example.com").is_err());
        changed = valid.clone();
        changed["category"] = json!("CREDIT_CARD");
        assert!(verified_login(&changed, &meta, "https://example.com").is_err());
    }
}
