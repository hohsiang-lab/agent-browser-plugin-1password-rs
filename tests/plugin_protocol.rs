#![cfg(unix)]
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("ab-op-plugin-test-{}-{}", std::process::id(), nanos));
    fs::create_dir(&path).unwrap();
    path
}

fn invoke(request: Value, setup: bool) -> Value {
    let dir = temp_dir();
    let config_path = dir.join("config.json");
    let op_path = dir.join("fake-op");
    if setup {
        fs::write(
            &config_path,
            json!({
                "profiles": { "test": {
                    "vault": "vault-id",
                    "item": "item-id",
                    "item_ref": "Test Login",
                    "login_url": "https://example.com/login"
                }}
            }).to_string(),
        ).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&op_path, r##"#!/bin/sh
[ "$OP_SERVICE_ACCOUNT_TOKEN" = "fake-test-token" ] || exit 1
[ "$1" = "item" ] && [ "$2" = "get" ] && [ "$3" = "item-id" ] || exit 1
[ "$4" = "--vault" ] && [ "$5" = "vault-id" ] || exit 1
printf '%s\n' '{"id":"item-id","vault":{"id":"vault-id"},"category":"LOGIN","urls":[{"href":"https://example.com/login"}],"fields":[{"purpose":"USERNAME","value":"alice@example.com"},{"purpose":"PASSWORD","value":"FAKE-PASSWORD-FOR-TESTS"}]}'
"##).unwrap();
        fs::set_permissions(&op_path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-browser-plugin-1password"))
        .env("AB_OP_CONFIG", &config_path)
        .env("AB_OP_BINARY", &op_path)
        .env("OP_SERVICE_ACCOUNT_TOKEN", "fake-test-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(request.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    fs::remove_dir_all(dir).unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn manifest_needs_no_vault_or_token() {
    let out = invoke(json!({
        "protocol":"agent-browser.plugin.v1", "type":"plugin.manifest",
        "capability":"plugin.manifest", "request":{}
    }), false);
    assert_eq!(out["success"], true);
    assert_eq!(out["manifest"]["capabilities"][0], "credential.read");
}

#[test]
fn returns_login_only_for_allowlisted_origin_and_item() {
    let out = invoke(json!({
        "protocol":"agent-browser.plugin.v1", "type":"credential.resolve",
        "capability":"credential.read", "request":{
            "profileName":"test","itemRef":"Test Login", "url":"https://example.com/login"
        }
    }), true);
    assert_eq!(out["success"], true);
    assert_eq!(out["credential"]["username"], "alice@example.com");
    assert_eq!(out["credential"]["password"], "FAKE-PASSWORD-FOR-TESTS");
}

#[test]
fn does_not_return_credentials_to_other_origin() {
    let out = invoke(json!({
        "protocol":"agent-browser.plugin.v1", "type":"credential.resolve",
        "capability":"credential.read", "request":{
            "profileName":"test","itemRef":"Test Login", "url":"https://malicious.example/login"
        }
    }), true);
    assert_eq!(out["success"], false);
    assert!(out.get("credential").is_none());
}

#[test]
fn never_performs_arbitrary_item_lookup() {
    let out = invoke(json!({
        "protocol":"agent-browser.plugin.v1", "type":"credential.resolve",
        "capability":"credential.read", "request":{
            "profileName":"test","itemRef":"different-item-id", "url":"https://example.com"
        }
    }), true);
    assert_eq!(out["success"], false);
    assert!(out.get("credential").is_none());
}
