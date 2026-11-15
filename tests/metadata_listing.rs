#![cfg(unix)]
// End-to-end protocol tests using a fake 1Password CLI. No real Vault access.
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn fake_op() -> &'static str {
    r##"#!/bin/sh
[ "$OP_SERVICE_ACCOUNT_TOKEN" = "FAKE_TEST_TOKEN" ] || exit 1
if [ "$1" = "vault" ] && [ "$2" = "list" ] && [ "$3" = "--format" ] && [ "$4" = "json" ]; then
  printf '%s\n' '[{"id":"vault1","name":"Automation","type":"USER_CREATED","secret":"NEVER-LEAK"},{"id":"vault2","name":"Other","type":"USER_CREATED","notes":"NEVER-LEAK"}]'
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "list" ] && [ "$3" = "--format" ] && [ "$4" = "json" ]; then
  printf '%s\n' '[{"id":"login1","title":"QA Manager 10","category":"LOGIN","vault":{"id":"vault1","name":"Automation"},"urls":[{"href":"https://hoh-i-carebridge.work/login?token=NEVER-LEAK"}],"fields":[{"value":"NEVER-LEAK"}],"password":"NEVER-LEAK"},{"id":"api1","title":"API key","category":"API_CREDENTIAL","vault":{"id":"vault1","name":"Automation"},"password":"NEVER-LEAK","notesPlain":"NEVER-LEAK"},{"id":"login2","title":"Other domain","category":"LOGIN","vault":{"id":"vault2","name":"Other"},"urls":[{"href":"https://other.example/login"}],"username":"NEVER-LEAK"}]'
  exit 0
fi
# Deliberately reject item get: metadata commands must never fetch secrets.
exit 1
"##
}

fn request(kind: &str, body: Value) -> Value {
    json!({
        "protocol": "agent-browser.plugin.v1",
        "type": kind,
        "capability": kind,
        "request": body
    })
}

fn invoke(payload: Value) -> Value {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
    let suffix = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ab-op-inventory-test-{}-{}-{}",
        std::process::id(),
        nanos,
        suffix
    ));
    fs::create_dir(&path).unwrap();
    let fake = path.join("op");
    fs::write(&fake, fake_op()).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-browser-plugin-1password"));
    command
        .env("AB_OP_BINARY", &fake)
        .env("OP_SERVICE_ACCOUNT_TOKEN", "FAKE_TEST_TOKEN")
        .env_remove("OP_CONNECT_HOST")
        .env_remove("OP_CONNECT_TOKEN");
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    fs::remove_dir_all(path).unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn manifest_exposes_both_read_only_inventory_capabilities() {
    let response = invoke(request("plugin.manifest", json!({})));
    let caps = response["manifest"]["capabilities"].as_array().unwrap();
    assert!(caps.contains(&json!("credential.read")));
    assert!(caps.contains(&json!("vault.list")));
    assert!(caps.contains(&json!("vault.items.list")));
}

#[test]
fn vault_list_returns_only_allowlisted_metadata() {
    let response = invoke(request("vault.list", json!({})));
    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["total"], 2);
    let vaults = response["data"]["vaults"].as_array().unwrap();
    assert_eq!(vaults[0]["name"], "Automation");
    assert_eq!(vaults[0]["id"], "vault1");
    assert_eq!(vaults[1]["name"], "Other");
    assert!(!response.to_string().contains("NEVER-LEAK"));
}

#[test]
fn item_list_covers_all_categories_but_never_fields_or_secrets() {
    let response = invoke(request("vault.items.list", json!({})));
    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["total"], 3);
    let items = response["data"]["items"].as_array().unwrap();
    assert!(items.iter().any(|item| item["category"] == "LOGIN"));
    assert!(items.iter().any(|item| item["category"] == "API_CREDENTIAL"));
    let login = items.iter().find(|item| item["id"] == "login1").unwrap();
    assert_eq!(login["websiteOrigins"], json!(["https://hoh-i-carebridge.work"]));
    for denied in ["NEVER-LEAK", "notesPlain", "password", "fields", "username"] {
        assert!(!response.to_string().contains(denied), "leaked: {denied}");
    }
}

#[test]
fn supports_exact_origin_category_vault_query_and_pagination() {
    let selected = invoke(request(
        "vault.items.list",
        json!({
            "vaultId": "vault1",
            "origin": "https://hoh-i-carebridge.work/login",
            "category": "login",
            "query": "manager",
            "limit": 1,
            "offset": 0
        }),
    ));
    assert_eq!(selected["data"]["total"], 1);
    assert_eq!(selected["data"]["items"][0]["id"], "login1");
    let all_vault = invoke(request(
        "vault.items.list",
        json!({"vaultId":"vault1","limit":1}),
    ));
    assert_eq!(all_vault["data"]["total"], 2);
    assert_eq!(all_vault["data"]["nextOffset"], 1);
    let second = invoke(request(
        "vault.items.list",
        json!({"vaultId":"vault1","limit":1,"offset":1}),
    ));
    assert_eq!(second["data"]["nextOffset"], Value::Null);
    assert_ne!(all_vault["data"]["items"], second["data"]["items"]);
    let named_vault = invoke(request("vault.list", json!({"query": "other"})));
    assert_eq!(named_vault["data"]["total"], 1);
    assert_eq!(named_vault["data"]["vaults"][0]["id"], "vault2");
}

#[test]
fn rejects_unsafe_requests_and_mismatched_capabilities() {
    for body in [
        json!({"origin":"http://hoh-i-carebridge.work"}),
        json!({"origin":"https://hoh-i-carebridge.work.evil.tld","extra":true}),
        json!({"vaultId":"-bad id"}),
        json!({"limit":201}),
        json!({"offset":-1}),
        json!({"unknown":"value"}),
    ] {
        let result = invoke(request("vault.items.list", body));
        assert_eq!(result["success"], false);
        assert!(result.get("data").is_none());
    }
    let mut mismatched = request("vault.items.list", json!({}));
    mismatched["capability"] = json!("credential.read");
    assert_eq!(invoke(mismatched)["success"], false);
}
