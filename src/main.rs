//! Agent Browser credential.read plugin for the 1Password CLI.
//! Only locally allowlisted profile -> vault/item/origin mappings can resolve credentials.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use url::Url;

const PROTOCOL: &str = "agent-browser.plugin.v1";
const MAX_INPUT_BYTES: u64 = 65_536;
const MAX_OP_OUTPUT_BYTES: usize = 1_048_576;

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
struct Config {
    profiles: HashMap<String, Profile>,
    #[serde(default)]
    keychain: Option<Keychain>,
}

#[derive(Deserialize)]
struct Profile {
    vault: String,
    item: String,
    #[serde(default)]
    item_ref: Option<String>,
    login_url: String,
}

#[derive(Deserialize)]
struct Keychain {
    service: String,
    account: String,
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

#[derive(Debug, PartialEq)]
struct Login {
    username: String,
    password: String,
}

fn main() {
    // Never log raw requests, secrets, CLI output, or tokens.
    let response = match run() {
        Ok(value) => value,
        Err(_) => json!({
            "protocol": PROTOCOL,
            "success": false,
            "error": "credential unavailable or request not authorized"
        }),
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &response).is_ok() {
        let _ = stdout.write_all(b"\n");
    }
}

fn run() -> Result<Value, ()> {
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() as u64 > MAX_INPUT_BYTES {
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
                "description": "Restricted 1Password CLI login credentials (Rust)"
            }
        }));
    }

    if envelope.request_type != "credential.resolve" || envelope.capability != "credential.read" {
        return Err(());
    }
    let request: ResolveRequest = serde_json::from_value(envelope.request).map_err(|_| ())?;
    let config = read_config()?;
    let profile = config.profiles.get(&request.profile_name).ok_or(())?;
    authorize(profile, &request)?;

    let token = acquire_service_token(config.keychain.as_ref())?;
    let op_json = run_op(profile, &token)?;
    let login = parse_login(&op_json, profile)?;
    Ok(json!({
        "protocol": PROTOCOL,
        "success": true,
        "credential": {
            "username": login.username,
            "password": login.password,
            "url": profile.login_url
        }
    }))
}

fn default_config_path() -> Result<PathBuf, ()> {
    let home = env::var_os("HOME").ok_or(())?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("agent-browser-plugin-1password")
        .join("config.json"))
}

fn read_config() -> Result<Config, ()> {
    let path = match env::var_os("AB_OP_CONFIG") {
        Some(value) => PathBuf::from(value),
        None => default_config_path()?,
    };
    let meta = fs::metadata(&path).map_err(|_| ())?;
    if !meta.is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(()); // owner-only config
        }
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    if bytes.len() > MAX_INPUT_BYTES as usize {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn origin(url: &str) -> Result<String, ()> {
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

fn authorize(profile: &Profile, request: &ResolveRequest) -> Result<(), ()> {
    if profile.vault.trim().is_empty() || profile.item.trim().is_empty() {
        return Err(());
    }
    let approved_origin = origin(&profile.login_url)?;
    if let Some(ref requested) = request.url {
        if origin(requested)? != approved_origin {
            return Err(());
        }
    }
    if let Some(ref item_ref) = request.item_ref {
        if item_ref != &profile.item && Some(item_ref) != profile.item_ref.as_ref() {
            return Err(());
        }
    }
    Ok(())
}

/// Token never appears in argv/config/errors.
fn acquire_service_token(keychain: Option<&Keychain>) -> Result<String, ()> {
    if let Ok(token) = env::var("OP_SERVICE_ACCOUNT_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(token);
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(kc) = keychain {
        if kc.service.is_empty() || kc.account.is_empty() {
            return Err(());
        }
        let result = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                &kc.service,
                "-a",
                &kc.account,
                "-w",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ())?;
        if !result.status.success() || result.stdout.len() > 8192 {
            return Err(());
        }
        let token = String::from_utf8(result.stdout).map_err(|_| ())?;
        let token = token.trim().to_owned();
        if !token.is_empty() {
            return Ok(token);
        }
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(kc) = keychain {
        let _ = (&kc.service, &kc.account);
    }
    Err(())
}

fn run_op(profile: &Profile, token: &str) -> Result<Value, ()> {
    let op_binary = env::var("AB_OP_BINARY").unwrap_or_else(|_| "op".to_owned());
    if op_binary.is_empty() {
        return Err(());
    }
    let mut command = Command::new(op_binary);
    command
        .args([
            "item",
            "get",
            &profile.item,
            "--vault",
            &profile.vault,
            "--format",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    // Do not propagate unrelated secrets from MCP host environment.
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "SSL_CERT_FILE",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
    ] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("OP_SERVICE_ACCOUNT_TOKEN", token)
        .env("OP_LOAD_DESKTOP_APP_SETTINGS", "false")
        .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false");
    let output = command.output().map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() > MAX_OP_OUTPUT_BYTES {
        return Err(());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| ())
}

fn field_value(item: &Value, purpose: &str, label: &str) -> Result<String, ()> {
    let fields = item.get("fields").and_then(Value::as_array).ok_or(())?;
    let by_purpose: Vec<&str> = fields
        .iter()
        .filter(|f| {
            f.get("purpose")
                .and_then(Value::as_str)
                .is_some_and(|p| p.eq_ignore_ascii_case(purpose))
        })
        .filter_map(|f| f.get("value").and_then(Value::as_str))
        .collect();
    let matches = if by_purpose.is_empty() {
        fields
            .iter()
            .filter(|f| {
                f.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.eq_ignore_ascii_case(label))
                    || f.get("label")
                        .and_then(Value::as_str)
                        .is_some_and(|s| s.eq_ignore_ascii_case(label))
            })
            .filter_map(|f| f.get("value").and_then(Value::as_str))
            .collect::<Vec<_>>()
    } else {
        by_purpose
    };
    if matches.len() != 1 || matches[0].is_empty() || matches[0].len() > 16_384 {
        return Err(());
    }
    Ok(matches[0].to_owned())
}

fn parse_login(item: &Value, profile: &Profile) -> Result<Login, ()> {
    if item.get("id").and_then(Value::as_str) != Some(profile.item.as_str()) {
        return Err(());
    }
    let vault = item.get("vault").ok_or(())?;
    if vault.get("id").and_then(Value::as_str) != Some(profile.vault.as_str())
        && vault.get("name").and_then(Value::as_str) != Some(profile.vault.as_str())
    {
        return Err(());
    }
    if !item
        .get("category")
        .and_then(Value::as_str)
        .is_some_and(|v| v.eq_ignore_ascii_case("LOGIN"))
    {
        return Err(());
    }
    let expected_origin = origin(&profile.login_url)?;
    let approved = item
        .get("urls")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .filter_map(|u| u.get("href").and_then(Value::as_str))
        .any(|u| origin(u).ok().as_ref() == Some(&expected_origin));
    if !approved {
        return Err(());
    }
    Ok(Login {
        username: field_value(item, "USERNAME", "username")?,
        password: field_value(item, "PASSWORD", "password")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        Profile {
            vault: "vault-id".to_string(),
            item: "item-id".to_string(),
            item_ref: Some("Demo Login".to_string()),
            login_url: "https://example.com/login".to_string(),
        }
    }
    fn sample_item() -> Value {
        json!({
            "id": "item-id",
            "vault": {"id": "vault-id", "name": "Demo"},
            "category": "LOGIN",
            "urls": [{"href": "https://example.com/login"}],
            "fields": [
                {"purpose": "USERNAME", "value": "alice@example.com"},
                {"purpose": "PASSWORD", "value": "fake-test-password"}
            ]
        })
    }
    #[test]
    fn resolves_only_approved_login() {
        let login = parse_login(&sample_item(), &profile()).unwrap();
        assert_eq!(login.username, "alice@example.com");
        assert_eq!(login.password, "fake-test-password");
    }
    #[test]
    fn rejects_cross_origin() {
        let r = ResolveRequest {
            profile_name: "demo".into(),
            item_ref: None,
            url: Some("https://evil.example/login".into()),
        };
        assert!(authorize(&profile(), &r).is_err());
    }
    #[test]
    fn rejects_unapproved_item_ref() {
        let r = ResolveRequest {
            profile_name: "demo".into(),
            item_ref: Some("other-item".into()),
            url: None,
        };
        assert!(authorize(&profile(), &r).is_err());
    }
    #[test]
    fn rejects_unmatched_1password_url() {
        let mut item = sample_item();
        item["urls"][0]["href"] = json!("https://other.example/login");
        assert!(parse_login(&item, &profile()).is_err());
    }
    #[test]
    fn rejects_wrong_vault() {
        let mut item = sample_item();
        item["vault"]["id"] = json!("another-vault");
        item["vault"]["name"] = json!("another-name");
        assert!(parse_login(&item, &profile()).is_err());
    }
    #[test]
    fn rejects_non_https() {
        assert!(origin("http://example.com/login").is_err());
        assert!(origin("https://u:p@example.com/login").is_err());
    }
    #[test]
    fn rejects_non_login_item() {
        let mut item = sample_item();
        item["category"] = json!("CREDIT_CARD");
        assert!(parse_login(&item, &profile()).is_err());
    }
}
