#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import sys


def generate_id_secret(client_id: str | None, client_secret: str | None) -> tuple[str, str]:
    cid = client_id or secrets.token_urlsafe(16)
    csec = client_secret or secrets.token_urlsafe(48)
    return cid, csec


def merged_oauth_clients(new_id: str, new_secret: str) -> str:
    raw = os.getenv("OAUTH_CLIENTS", "{}")
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            obj = {}
    except Exception:
        obj = {}
    obj[new_id] = new_secret
    return json.dumps(obj)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate analyzer OAuth client_id and client_secret")
    ap.add_argument("--client-id", dest="client_id", default=None, help="Optional custom client id")
    ap.add_argument("--client-secret", dest="client_secret", default=None, help="Optional custom client secret")
    ap.add_argument("--signing-key", dest="signing_key", default=None, help="Optional custom OAUTH_SIGNING_KEY (HS256)")
    args = ap.parse_args()

    client_id, client_secret = generate_id_secret(args.client_id, args.client_secret)
    oauth_clients_value = merged_oauth_clients(client_id, client_secret)
    signing_key = args.signing_key or secrets.token_urlsafe(64)

    print("== Analyzer Credentials ==")
    print(f"client_id:    {client_id}")
    print(f"client_secret: {client_secret}")
    print(f"OAUTH_SIGNING_KEY: {signing_key}")
    print()
    print("== Set on analyzer (env) ==")
    print("# Add/merge into OAUTH_CLIENTS (JSON map of id->secret)")
    print("OAUTH_CLIENTS='" + oauth_clients_value + "'")
    print(f"OAUTH_SIGNING_KEY='{signing_key}'")
    print()
    print("== Set on vibefunder (env) ==")
    print(f"ANALYZER_CLIENT_ID={client_id}")
    print(f"ANALYZER_CLIENT_SECRET={client_secret}")
    print()
    print("Notes:")
    print("- Keep OAUTH_SIGNING_KEY secret; rotate periodically.")
    print("- After updating env, redeploy/restart analyzer to apply changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


