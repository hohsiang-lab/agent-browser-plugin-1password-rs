#![cfg(unix)]
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> PathBuf {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ab-op-integration-{}-{}-{}",
            std::process::id(),
            nanos,
            unique
        ));
        match fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("temporary directory creation failed: {error}"),
        }
    }
    panic!("unable to create temporary directory");
}

fn fake_op() -> &'static str {
    r##"#!/bin/sh
[ "$OP_SERVICE_ACCOUNT_TOKEN" = "FAKE_TEST_TOKEN" ] || exit 1
if [ "$1" = "item" ] && [ "$2" = "list" ]; then
  if [ "$MOCK_CASE" = "oversized_list" ]; then
    head -c 1100000 /dev/zero | tr '\\000' 'X'
    exit 0
  fi
  case "$MOCK_CASE" in
    no_match)
      printf '%s\n' '[{"id":"evil","title":"Evil","vault":{"id":"v-evil"},"urls":[{"href":"https://example.com.evil.tld"}]}]'
      ;;
    ambiguous)
      printf '%s\n' '[{"id":"first","title":"Test Account","vault":{"id":"v-test"},"urls":[{"href":"https://example.com/login"}]},{"id":"second","title":"Test Account","vault":{"id":"v-test"},"urls":[{"href":"https://example.com/sign-in"}]}]'
      ;;
    *)
      printf '%s\n' '[{"id":"first","title":"Test Account","vault":{"id":"v-test"},"urls":[{"href":"https://example.com/login"},{"href":"https://example.org/login"}]}]'
      ;;
  esac
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "get" ]; then
  [ "$3" = "first" ] || exit 1
  [ "$4" = "--vault" ] && [ "$5" = "v-test" ] || exit 1
  if [ "$6" = "--otp" ]; then
    [ "$MOCK_CASE" = "no_otp" ] && exit 1
    printf '%s\n' '123456'
    exit 0
  fi
  [ "$6" = "--format" ] && [ "$7" = "json" ] || exit 1
  if [ "$MOCK_CASE" = "changed_origin" ]; then
    printf '%s\n' '{"id":"first","category":"LOGIN","vault":{"id":"v-test"},"urls":[{"href":"https://attacker.example/login"}],"fields":[{"purpose":"USERNAME","value":"alice"},{"purpose":"PASSWORD","value":"FAKE-SECRET"}]}'
  else
    printf '%s\n' '{"id":"first","category":"LOGIN","vault":{"id":"v-test"},"urls":[{"href":"https://example.com/login"},{"href":"https://example.org/login"}],"fields":[{"purpose":"USERNAME","value":"alice@example.com"},{"purpose":"PASSWORD","value":"FAKE-SECRET"}]}'
  fi
  exit 0
fi
exit 1
"##
}

fn invoke(request: Value, case: &str, allowed: Option<&str>) -> Value {
    let dir = temp_dir();
    let fake = dir.join("op");
    fs::write(&fake, fake_op().replace("$MOCK_CASE", case)).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-browser-plugin-1password"));
    command
        .env("AB_OP_BINARY", &fake)
        .env("OP_SERVICE_ACCOUNT_TOKEN", "FAKE_TEST_TOKEN")
        .env("MOCK_CASE", case)
        .env_remove("OP_CONNECT_HOST")
        .env_remove("OP_CONNECT_TOKEN")
        .env_remove("AB_OP_ALLOWED_ORIGINS");
    if let Some(origins) = allowed {
        command.env("AB_OP_ALLOWED_ORIGINS", origins);
    }
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
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    fs::remove_dir_all(dir).unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn resolve(url: Option<&str>, item: Option<&str>) -> Value {
    json!({
        "protocol": "agent-browser.plugin.v1",
        "type": "credential.resolve",
        "capability": "credential.read",
        "request": {
            "profileName": "test",
            "itemRef": item,
            "url": url
        }
    })
}

#[test]
fn manifests_without_credentials() {
    let output = invoke(
        json!({
            "protocol":"agent-browser.plugin.v1",
            "type":"plugin.manifest",
            "capability":"plugin.manifest",
            "request":{}
        }),
        "",
        None,
    );
    assert_eq!(output["success"], true);
    assert_eq!(output["manifest"]["capabilities"][0], "credential.read");
}

#[test]
fn auto_selects_only_matching_login_and_returns_optional_otp() {
    let output = invoke(resolve(Some("https://example.com/login"), None), "", None);
    assert_eq!(output["success"], true);
    assert_eq!(output["credential"]["username"], "alice@example.com");
    assert_eq!(output["credential"]["password"], "FAKE-SECRET");
    assert_eq!(output["credential"]["otp"], "123456");
}

#[test]
fn no_otp_is_valid_login() {
    let output = invoke(
        resolve(Some("https://example.com/login"), None),
        "no_otp",
        None,
    );
    assert_eq!(output["success"], true);
    assert!(output["credential"].get("otp").is_none());
}

#[test]
fn accepts_a_second_saved_website() {
    let output = invoke(resolve(Some("https://example.org/signin"), None), "", None);
    assert_eq!(output["success"], true);
}

#[test]
fn refuses_missing_url() {
    let output = invoke(resolve(None, None), "", None);
    assert_eq!(output["success"], false);
    assert!(output.get("credential").is_none());
}

#[test]
fn refuses_similar_but_different_origin() {
    let output = invoke(
        resolve(Some("https://example.com.evil.tld/login"), None),
        "",
        None,
    );
    assert_eq!(output["success"], false);
    assert!(output.get("credential").is_none());
}

#[test]
fn refuses_wrong_or_changed_item_url() {
    let output = invoke(
        resolve(Some("https://example.com/login"), None),
        "changed_origin",
        None,
    );
    assert_eq!(output["success"], false);
    assert!(output.get("credential").is_none());
}

#[test]
fn multiple_accounts_need_exact_item_selection() {
    let without_item = invoke(
        resolve(Some("https://example.com/login"), None),
        "ambiguous",
        None,
    );
    assert_eq!(without_item["success"], false);
    let exact_id = invoke(
        resolve(Some("https://example.com/login"), Some("op:first")),
        "ambiguous",
        None,
    );
    assert_eq!(exact_id["success"], true);
    let duplicate_title = invoke(
        resolve(Some("https://example.com/login"), Some("Test Account")),
        "ambiguous",
        None,
    );
    assert_eq!(duplicate_title["success"], false);
}

#[test]
fn optional_local_origin_allowlist() {
    let refused = invoke(
        resolve(Some("https://example.com/login"), None),
        "",
        Some("https://example.org"),
    );
    assert_eq!(refused["success"], false);
    let accepted = invoke(
        resolve(Some("https://example.com/login"), None),
        "",
        Some("https://example.com,https://example.org"),
    );
    assert_eq!(accepted["success"], true);
    let empty = invoke(
        resolve(Some("https://example.com/login"), None),
        "",
        Some(""),
    );
    assert_eq!(empty["success"], false);
}

#[test]
fn rejects_oversized_cli_output() {
    let result = invoke(resolve(Some("https://example.com/login"), None), "oversized_list", None);
    assert_eq!(result["success"], false);
    assert!(result.get("credential").is_none());
}
