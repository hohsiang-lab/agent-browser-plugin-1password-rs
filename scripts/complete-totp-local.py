#!/usr/bin/env python3
"""Complete a second-page TOTP challenge from a 1Password Login Item.

Runs entirely on the Mac beside agent-browser. Retrieves a fresh 6-digit OTP
from the selected, exactly origin-matched 1Password Login Item and supplies it
over stdin to agent-browser eval. Never prints or persists the OTP, token,
credentials, Item IDs, vault names, raw CLI responses, or page contents.

This is an explicit local operator action, not a remotely callable credential
read capability.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit


def fail(step):
    print(step + ": FAIL")
    return 1


def target_origin(url):
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        port = parsed.port or 443
        return (parsed.hostname.lower(), port)
    except (TypeError, ValueError):
        return None


def matches_site(item, site):
    urls = item.get("urls") or []
    return isinstance(urls, list) and any(
        isinstance(v, dict) and target_origin(v.get("href")) == site
        for v in urls
    )


def run(args, env, stdin=None, timeout=20):
    try:
        return subprocess.run(
            args,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Finish an existing staging TOTP page via local 1Password OTP"
    )
    parser.add_argument("--url", required=True, help="Expected staging login URL")
    parser.add_argument("--item", required=True, help="Exact Login Item title or ID")
    parser.add_argument("--session", required=True, help="Existing agent-browser session")
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", args.session):
        return fail("Session validation")
    site = target_origin(args.url)
    if not site:
        return fail("HTTPS origin validation")
    if not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
        return fail("Service Account environment")
    op = shutil.which("op")
    browser = shutil.which("agent-browser")
    if not op or not browser:
        return fail("Required local tools")

    op_env = dict(os.environ)
    items_response = run(
        [op, "item", "list", "--categories", "Login", "--format", "json"],
        env=op_env,
    )
    if items_response is None or items_response.returncode:
        return fail("1Password Login list")
    try:
        items = json.loads(items_response.stdout)
        if not isinstance(items, list):
            return fail("Login metadata")
        matches = [
            item
            for item in items
            if isinstance(item, dict)
            and isinstance(item.get("id"), str) and item["id"]
            and isinstance(item.get("vault"), dict)
            and isinstance(item["vault"].get("id"), str)
            and item["vault"]["id"]
            and matches_site(item, site)
            and (
                item["id"] == args.item
                or item.get("title") == args.item
            )
        ]
    except (ValueError, TypeError):
        return fail("Login metadata")
    if len(matches) != 1:
        return fail("Unique Login Item and origin selection")
    print("Unique Login Item and origin selection: PASS")

    selected = matches[0]
    result = run(
        [op, "item", "get", selected["id"], "--vault", selected["vault"]["id"], "--otp"],
        env=op_env,
        timeout=15,
    )
    if result is None or result.returncode:
        return fail("1Password TOTP read")
    try:
        otp = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        otp = ""
    if not re.fullmatch(r"[0-9]{6}", otp):
        return fail("1Password six-digit TOTP")
    print("1Password six-digit TOTP: PASS")

    scheme_host = f"https://{site[0]}" + (f":{site[1]}" if site[1] != 443 else "")
    # Strictly check the actual browser page origin and /totp path before filling.
    # The native setter + bubbling input event triggers React controlled inputs.
    script = """
(async () => {
  const expectedOrigin = %s;
  const code = %s;
  if (location.origin !== expectedOrigin || location.pathname !== '/totp')
    throw new Error('wrong origin or not on TOTP challenge');
  const inputs = [...document.querySelectorAll('input')].filter(
    e => e.getClientRects().length > 0 && !e.disabled && !e.readOnly
  );
  if (inputs.length !== 1) throw new Error('ambiguous TOTP field');
  const input = inputs[0];
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype, 'value'
  ).set;
  setter.call(input, code);
  input.dispatchEvent(new InputEvent('input', {
    bubbles: true, inputType: 'insertText', data: code
  }));
  input.dispatchEvent(new Event('change', {bubbles: true}));
  await new Promise(resolve => setTimeout(resolve, 350));
  const buttons = [...document.querySelectorAll('button')].filter(
    b => b.getClientRects().length > 0 &&
         b.innerText.trim() === '確認' && !b.disabled
  );
  if (buttons.length !== 1) throw new Error('confirm button unavailable');
  buttons[0].click();
  return 'TOTP_SUBMITTED';
})()
""" % (json.dumps(scheme_host), json.dumps(otp))

    # The browser CLI only needs its existing session, NOT the Service Account.
    browser_env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("OP_") and key != "AB_OP_BINARY"
    }
    result = run(
        [browser, "--session", args.session, "eval", "--stdin"],
        env=browser_env,
        stdin=script.encode("utf-8"),
        timeout=20,
    )
    if (
        result is None
        or result.returncode != 0
        or b"TOTP_SUBMITTED" not in result.stdout
    ):
        return fail("Browser TOTP submit")
    print("Browser TOTP submit: PASS")
    print("Verify resulting page via Agent Browser MCP; submission alone is not login success.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
