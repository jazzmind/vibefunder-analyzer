from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from dotenv import load_dotenv
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt


load_dotenv()  # allow local .env usage during development


OAUTH_SIGNING_KEY = os.getenv("OAUTH_SIGNING_KEY", "dev-signing-key-change-me")
OAUTH_ISSUER = os.getenv("OAUTH_ISSUER", "vibefunder-analyzer")
OAUTH_AUDIENCE = os.getenv("OAUTH_AUDIENCE", "analyzer-api")
OAUTH_TOKEN_TTL_SECONDS = int(os.getenv("OAUTH_TOKEN_TTL_SECONDS", "3600"))

_clients_env = os.getenv("OAUTH_CLIENTS", "{}")
try:
    OAUTH_CLIENTS: Dict[str, str] = json.loads(_clients_env)
except Exception:
    OAUTH_CLIENTS = {}


def issue_token(client_id: str, scope: Optional[str] = None) -> Dict[str, object]:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(seconds=OAUTH_TOKEN_TTL_SECONDS)
    payload = {
        "sub": client_id,
        "iss": OAUTH_ISSUER,
        "aud": OAUTH_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "scope": scope or "analyze:write",
    }
    token = jwt.encode(payload, OAUTH_SIGNING_KEY, algorithm="HS256")
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": OAUTH_TOKEN_TTL_SECONDS,
        "scope": payload["scope"],
    }


def verify_token(token: str, required_scope: Optional[str] = None) -> Dict[str, object]:
    try:
        payload = jwt.decode(token, OAUTH_SIGNING_KEY, algorithms=["HS256"], audience=OAUTH_AUDIENCE, issuer=OAUTH_ISSUER)
    except jwt.PyJWTError as exc:  # type: ignore[attr-defined]
        raise HTTPException(status_code=401, detail=f"invalid_token: {exc}")
    if required_scope:
        scopes = str(payload.get("scope", "")).split()
        if required_scope not in scopes:
            raise HTTPException(status_code=403, detail="insufficient_scope")
    return payload


http_bearer = HTTPBearer(auto_error=False)


def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer)) -> Dict[str, object]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="missing_authorization")
    return verify_token(credentials.credentials)


def authenticate_client(client_id: str, client_secret: str) -> bool:
    expected = OAUTH_CLIENTS.get(client_id)
    if not expected:
        return False
    # Constant-time compare
    if len(expected) != len(client_secret):
        return False
    result = 0
    for x, y in zip(expected.encode(), client_secret.encode()):
        result |= x ^ y
    return result == 0


