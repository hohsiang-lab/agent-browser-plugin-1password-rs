#!/usr/bin/env python3
"""Local, redacted 1Password credential-provider diagnostic.

Reads only the selected Service Account's Login metadata and one matching item.
Never prints or logs item names, IDs, Vault names, URLs, usernames, passwords,
tokens, OTPs, op stderr, or raw plugin responses. Do not use with production
origins: run with a dedicated staging Test Login item and read-only Service
Account. Invoking credential.resolve never submits a browser login form.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit


def origin(value):
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        return (parsed.hostname.lower(), parsed.port or 443)
    except (TypeError, ValueError):
        return None


def websites_match(item, target):
    urls = item.get("urls") or []
    return isinstance(urls, list) and any(
        isinstance(entry, dict) and origin(entry.get("href")) == target
        for entry in urls
    )


def run(command, env, stdin=None, timeout=10):
    try:
        return subprocess.run(
            command,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def status(label, condition):
    print(f"{label}: {'PASS' if condition else 'FAIL'}")


def main():
    parser = argparse.ArgumentParser(
        description="Redacted Mac-local diagnostics for Agent Browser's 1Password Plugin"
    )
    parser.add_argument("--url", required=True, help="Explicit staging HTTPS login URL")
    parser.add_argument("--item", help="Exact Login Item ID/title if several share an origin")
    args = parser.parse_args()

    target = origin(args.url)
    if target is None:
        print("Target origin: INVALID (requires HTTPS)")
        return 2

    token = os.environ.get("OP_SERVICE_ACCOUNT_TOKEN", "")
    status("Service Account token environment", bool(token))
    if not token:
        return 2

    binary = next(
        (p for p in ("/opt/homebrew/bin/op", "/usr/local/bin/op") if Path(p).is_file()),
        None,
    )
    status("1Password CLI executable", bool(binary))
    if not binary:
        return 2

    # Intentionally isolate CLI auth to the Service Account. Do not allow a
    # desktop session/Connect credentials to hide missing Service Account access.
    env = {
        "OP_SERVICE_ACCOUNT_TOKEN": token,
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(Path.home()),
        "USER": os.environ.get("USER", ""),
        "AB_OP_BINARY": binary,
    }
    if "AB_OP_ALLOWED_ORIGINS" in os.environ:
        env["AB_OP_ALLOWED_ORIGINS"] = os.environ["AB_OP_ALLOWED_ORIGINS"]

    result = run([binary, "item", "list", "--categories", "Login", "--format", "json"], env)
    list_ok = result is not None and result.returncode == 0
    status("Service Account Login list", list_ok)
    if not list_ok:
        return 1

    try:
        all_items = json.loads(result.stdout)
        if not isinstance(all_items, list):
            raise ValueError
    except (ValueError, TypeError):
        print("Login metadata JSON: FAIL")
        return 1
    print("Login metadata JSON: PASS")

    matches = [
        item
        for item in all_items
        if isinstance(item, dict)
        and isinstance(item.get("id"), str) and item["id"]
        and isinstance(item.get("vault"), dict)
        and isinstance(item["vault"].get("id"), str) and item["vault"]["id"]
        and websites_match(item, target)
    ]
    print(f"Matching Login Items: {len(matches)}")
    if args.item:
        name = args.item.removeprefix("op:")
        matches = [
            item for item in matches
            if item["id"] == name or item.get("title") == args.item
        ]
    if len(matches) != 1:
        print("Unique Login selection: FAIL (select exactly one match)")
        return 1
    print("Unique Login selection: PASS")
    item = matches[0]
    record = run(
        [binary, "item", "get", item["id"],
         "--vault", item["vault"]["id"], "--format", "json"],
        env,
    )
    read_ok = record is not None and record.returncode == 0
    status("Service Account Item read", read_ok)
    if not read_ok:
        return 1

    try:
        details = json.loads(record.stdout)
        fields = details.get("fields") or []
        if not isinstance(fields, list):
            raise ValueError
        def field_found(purpose, label):
            return sum(
                1 for field in fields
                if isinstance(field, dict)
                and isinstance(field.get("value"), str) and bool(field["value"])
                and (
                    str(field.get("purpose") or "").upper() == purpose
                    or str(field.get("id") or "").lower() == label
                    or str(field.get("label") or "").lower() == label
                )
            ) >= 1

        schema_ok = (
            details.get("id") == item["id"]
            and isinstance(details.get("vault"), dict)
            and details["vault"].get("id") == item["vault"]["id"]
            and str(details.get("category") or "").upper() == "LOGIN"
            and websites_match(details, target)
            and field_found("USERNAME", "username")
            and field_found("PASSWORD", "password")
        )
    except (ValueError, TypeError, AttributeError, KeyError):
        schema_ok = False
    status("Item metadata and login fields", schema_ok)
    if not schema_ok:
        return 1

    plugin = Path.home() / ".local/bin/agent-browser-plugin-1password"
    status("Plugin executable", plugin.is_file())
    if not plugin.is_file():
        return 1

    req = {
        "protocol": "agent-browser.plugin.v1",
        "type": "credential.resolve",
        "capability": "credential.read",
        "request": {
            "profileName": "staging-diagnostics",
            "url": args.url,
        },
    }
    if args.item:
        req["request"]["itemRef"] = args.item
    response = run(
        [str(plugin)], env, stdin=json.dumps(req).encode("utf-8"), timeout=15
    )
    try:
        success = (
            response is not None and response.returncode == 0
            and json.loads(response.stdout).get("success") is True
        )
    except (ValueError, TypeError, AttributeError):
        success = False
    status("Rust Plugin credential.resolve", success)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
