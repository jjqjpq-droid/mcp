#!/usr/bin/env python3
"""
Qwen Chat Remote MCP Server (Vercel serverless)
================================================

Architecture:
    Claude Web -> Custom Connector -> this MCP server (Vercel)
        -> Qwen (chat.qwen.ai) -> response back to Claude Web

Features:
  * Automatic Re-login & Token Refresh:
    - Dynamic handshake to fetch fresh edge cookies and tokens.
    - Automatic detection of 401 / 403 / revoked JWT / expired session.
    - On auth error, automatically invalidates dead tokens, performs fresh
      login, stores the new token & cookies, and retries the request seamlessly.
  * Robust Chat Session Management:
    - Tries creating new chat; automatically falls back to reusing active
      chats if WAF or server intercepts new chat creation.
  * Direct Re-login Endpoints:
    - GET / POST /relogin: Force an immediate fresh login and inspect token status.
    - GET /healthz: Live health and auth status report.
  * MCP Tools:
    - `qwen_chat`: Send message(s) and get complete generated answer.
    - `qwen_relogin`: Force re-login and token refresh directly from MCP.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

logger = logging.getLogger("qwen-mcp")
logging.basicConfig(level=logging.INFO)

# ============================================================================
# APNI DETAILS YAHAN DAALO  (code me hi — auto.py jaisa)
# ============================================================================
EMAIL = "nolis38086@airychen.com"        # apna Qwen email
PASSWORD = "nolis38086@airychen.com"   # plain password (script khud SHA256 karega)
ACW_TC = "0a03e59317893812264476536e23833f806baf8a57a09253f807c4d9486a43"
APP_WAF = "Z9Tr56YmQpXcO2K_d_3nAbJvRqMLFW8HTNjvRguWHEowM1xY"
# ============================================================================
# Fallback: agar upar blank chhoda ho toh Vercel env vars se uthaye jayenge
EMAIL = EMAIL or os.environ.get("QWEN_EMAIL", "").strip()
PASSWORD = PASSWORD or os.environ.get("QWEN_PASSWORD", "")
ACW_TC = ACW_TC or os.environ.get("QWEN_ACW_TC", "").strip()
APP_WAF = APP_WAF or os.environ.get("QWEN_APP_WAF", "").strip()
# ============================================================================

BASE = "https://chat.qwen.ai"
MODEL = os.environ.get("QWEN_MODEL", "qwen3.8-max").strip() or "qwen3.8-max"

MCP_API_KEY = os.environ.get("MCP_API_KEY", "").strip()   # OPTIONAL
QWEN_TOKEN = os.environ.get("QWEN_TOKEN", "").strip()     # OPTIONAL pre-seeded Qwen JWT

UA = ("Dalvik/2.1.0 (Linux; U; Android 16; V2502 Build/BP2A.250605.031.A3_V000L1) "
      "AliApp(QWENCHAT/2.4.0) AppType/Release AplusBridgeLite")

HEADERS = {
    "source": "app",
    "X-Platform": "android",
    "Accept-Language": "en-US",
    "Accept-Charset": "UTF-8",
    "User-Agent": UA,
}
if APP_WAF:
    HEADERS["app_waf"] = APP_WAF

MAX_MESSAGES = 50
MAX_CONTENT_CHARS = 20000  # per message


class QwenAuthError(Exception):
    """Raised when Qwen responds with 401, 403, or invalid/expired token."""
    pass


class QwenChatBusyError(Exception):
    """Raised when a specific chat session has a message currently in progress."""
    pass


# ----------------------------------------------------------------------------
# Token cache (in-memory, per warm serverless instance)
# ----------------------------------------------------------------------------

_cache_lock = threading.Lock()
_token_cache: dict[str, Any] = {
    "token": None,
    "exp": 0.0,
    "cookies": {},
    "invalidated_tokens": set(),
}


def _decode_jwt_exp(token: str) -> float:
    """Decode JWT exp claim without verifying signature."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return float(data.get("exp", 0) or 0)
    except Exception:
        return 0.0


def _jwt_expired(token: str) -> bool:
    """Check if token is expired or will expire within 5 minutes."""
    exp = _decode_jwt_exp(token)
    if exp <= 0:
        return True
    return time.time() > exp - 300


def extract_token(resp: requests.Response) -> str | None:
    """Extract token from JSON body, cookies, or raw text."""
    try:
        body = resp.json()
    except Exception:
        body = {}
    data = body.get("data") or {}
    for key in ("token", "access_token", "jwt"):
        if isinstance(data, dict) and data.get(key):
            return str(data[key])
    for c in resp.cookies:
        if c.name == "token":
            return c.value
    txt = resp.text
    if "eyJ" in txt:
        i = txt.find("eyJ")
        j = txt.find('"', i)
        if j > i:
            return txt[i:j]
    return None


def login(force: bool = False) -> str | None:
    """Fetch fresh authentication token and session cookies.

    Performs dynamic edge handshake to ensure fresh edge/WAF cookies,
    then posts credentials to /api/v2/auths/signin.
    """
    if not EMAIL or not PASSWORD or "yahan_apna" in PASSWORD:
        logger.warning("Qwen credentials not configured in EMAIL/PASSWORD")
        return None

    s = requests.Session()
    # Dynamic edge handshake with correct UA
    try:
        s.get(f"{BASE}/", headers={"User-Agent": UA}, timeout=10)
    except Exception as e:
        logger.debug("Edge handshake exception: %s", e)

    if ACW_TC and "acw_tc" not in s.cookies:
        s.cookies.set("acw_tc", ACW_TC, domain="chat.qwen.ai")
    s.cookies.set("x-ap", "ap-southeast-1", domain="chat.qwen.ai")

    hashed = hashlib.sha256(PASSWORD.encode()).hexdigest()
    try:
        r = s.post(
            f"{BASE}/api/v2/auths/signin",
            headers={**HEADERS, "Accept": "application/json", "Content-Type": "application/json"},
            json={"email": EMAIL, "password": hashed},
            timeout=20,
        )
    except requests.RequestException as e:
        logger.warning("Qwen signin request error: %s", type(e).__name__)
        return None

    if r.status_code != 200:
        logger.warning("Qwen signin returned HTTP %s", r.status_code)
        return None

    token = extract_token(r)
    if token:
        logger.info("Qwen login successful, acquired fresh token")
        with _cache_lock:
            _token_cache["token"] = token
            _token_cache["exp"] = _decode_jwt_exp(token)
            _token_cache["cookies"] = dict(s.cookies)
            _token_cache["invalidated_tokens"].discard(token)
        return token

    logger.warning("Qwen login failed: no token found in response body or cookies")
    return None


def get_token(force_refresh: bool = False) -> tuple[str | None, dict[str, str]]:
    """Return valid token and associated cookies.

    If cached token is valid and not forced, returns cached token.
    Otherwise triggers fresh login, updates cache, and returns fresh token.
    """
    with _cache_lock:
        tok = _token_cache["token"]
        if (not force_refresh
                and tok
                and not _jwt_expired(tok)
                and tok not in _token_cache["invalidated_tokens"]):
            return tok, dict(_token_cache.get("cookies") or {})

        # Check env-seeded token if not invalidated
        if (not force_refresh
                and QWEN_TOKEN
                and not _jwt_expired(QWEN_TOKEN)
                and QWEN_TOKEN not in _token_cache["invalidated_tokens"]):
            _token_cache["token"] = QWEN_TOKEN
            _token_cache["exp"] = _decode_jwt_exp(QWEN_TOKEN)
            return QWEN_TOKEN, dict(_token_cache.get("cookies") or {})

    fresh = login(force=True)
    with _cache_lock:
        if fresh:
            return fresh, dict(_token_cache.get("cookies") or {})
        _token_cache["token"] = None
        _token_cache["exp"] = 0.0
        return None, dict(_token_cache.get("cookies") or {})


def invalidate_token(token: str | None = None) -> None:
    """Invalidate current or given token so next request forces fresh login."""
    with _cache_lock:
        curr = token or _token_cache.get("token")
        if curr:
            _token_cache["invalidated_tokens"].add(curr)
        _token_cache["token"] = None
        _token_cache["exp"] = 0.0
        logger.info("Token invalidated; fresh login will be triggered.")


# ----------------------------------------------------------------------------
# Qwen HTTP client
# ----------------------------------------------------------------------------

def make_session(token: str | None = None,
                 cookies: dict[str, str] | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)

    if cookies:
        for k, v in cookies.items():
            s.cookies.set(k, v, domain="chat.qwen.ai")

    if ACW_TC and "acw_tc" not in s.cookies:
        s.cookies.set("acw_tc", ACW_TC, domain="chat.qwen.ai")
    if "x-ap" not in s.cookies:
        s.cookies.set("x-ap", "ap-southeast-1", domain="chat.qwen.ai")

    if token:
        s.cookies.set("token", token, domain="chat.qwen.ai")
        s.headers["Authorization"] = f"Bearer {token}"

    return s


def get_candidate_chats(session: requests.Session, mode: str) -> list[str]:
    """Retrieve ordered list of candidate chat IDs.

    Tries /api/v2/chats/new first. If new chat creation is restricted or fails,
    fetches existing active chats from /api/v2/chats so an idle session can be used.
    """
    candidates: list[str] = []

    # 1. Try creating a new chat
    try:
        r = session.post(
            f"{BASE}/api/v2/chats/new",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={"chat_mode": mode, "project_id": ""},
            timeout=15,
        )
        if r.status_code in (401, 403):
            raise QwenAuthError(f"HTTP {r.status_code} on chats/new")
        if r.status_code == 200:
            try:
                body = r.json()
                if body.get("success") and "data" in body and "id" in body["data"]:
                    candidates.append(str(body["data"]["id"]))
            except Exception:
                pass
    except QwenAuthError:
        raise
    except Exception as e:
        logger.debug("chats/new non-auth error: %s", e)

    # 2. Fetch existing active chats as fallback / candidates
    try:
        r = session.get(
            f"{BASE}/api/v2/chats",
            headers={"Accept": "application/json"},
            timeout=15,
        )
        if r.status_code in (401, 403):
            raise QwenAuthError(f"HTTP {r.status_code} on chats list")
        if r.status_code == 200:
            body = r.json()
            if body.get("success") and body.get("data"):
                for item in body["data"]:
                    cid = str(item.get("id", ""))
                    if cid and cid not in candidates:
                        candidates.append(cid)
    except QwenAuthError:
        raise
    except Exception as e:
        logger.warning("Failed to fetch existing chats: %s", e)

    return candidates


def send_message(session: requests.Session, chat_id: str, mode: str,
                 messages: list[dict[str, str]]) -> tuple[bool, str]:
    """Collect SSE streamed completion into final answer string."""
    payload_messages: list[dict[str, Any]] = []
    for i, m in enumerate(messages):
        is_last = i == len(messages) - 1
        if is_last and m["role"] == "user":
            payload_messages.append({
                "chat_type": "t2t", "content": m["content"], "role": "user",
                "feature_config": {"output_schema": "phase", "thinking_enabled": True,
                                   "thinking_format": "summary", "auto_thinking": True,
                                   "auto_search": True},
                "sub_chat_type": "t2t", "models": [MODEL], "user_action": "chat",
            })
        else:
            payload_messages.append({"role": m["role"], "content": m["content"]})

    payload = {
        "stream": True, "incremental_output": True,
        "chat_id": chat_id, "chat_mode": mode, "model": MODEL,
        "messages": payload_messages,
        "share_id": "", "version": "2.1", "origin_branch_message_id": "",
    }

    try:
        with session.post(
            f"{BASE}/api/v2/chat/completions",
            params={"chat_id": chat_id},
            headers={"Accept": "*/*,text/event-stream", "Cache-Control": "no-store",
                     "Content-Type": "application/json; charset=UTF-8"},
            json=payload, stream=True, timeout=180,
        ) as r:
            if r.status_code in (401, 403):
                raise QwenAuthError(f"HTTP {r.status_code} on completions")
            if r.status_code != 200:
                logger.warning("Qwen completions returned HTTP %s", r.status_code)
                return False, ""

            answer = ""
            for line in r.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data or "response.created" in data:
                    continue
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue

                if not obj.get("success", True):
                    err_code = str(obj.get("data", {}).get("code", ""))
                    if err_code in ("UNAUTHORIZED", "Forbidden", "TOKEN_EXPIRED"):
                        raise QwenAuthError(f"Qwen stream error code: {err_code}")
                    if err_code == "CHAT_IN_PROGRESS":
                        raise QwenChatBusyError("A message is currently being generated in this chat.")
                    return False, ""

                for choice in obj.get("choices", []):
                    delta = choice.get("delta", {})
                    if delta.get("phase") == "answer":
                        if delta.get("content"):
                            answer += delta["content"]
                        if delta.get("status") == "finished":
                            return bool(answer), answer

            return bool(answer), answer
    except (QwenAuthError, QwenChatBusyError):
        raise
    except requests.RequestException as e:
        logger.warning("Qwen completions request error: %s", type(e).__name__)
        return False, ""


def _validate_messages(message: str | None,
                       messages: list[dict[str, str]] | None) -> list[dict[str, str]]:
    """Validate input and normalize to a clean [{role, content}, ...] list."""
    if messages is not None:
        if not isinstance(messages, list) or not messages:
            raise ValueError("'messages' must be a non-empty array of {role, content} objects.")
        if len(messages) > MAX_MESSAGES:
            raise ValueError(f"'messages' is limited to {MAX_MESSAGES} entries.")
        cleaned = []
        for i, m in enumerate(messages):
            role = m.get("role") if isinstance(m, dict) else None
            content = m.get("content") if isinstance(m, dict) else None
            if (role not in ("user", "assistant", "system")
                    or not isinstance(content, str)
                    or not content.strip()
                    or len(content) > MAX_CONTENT_CHARS):
                raise ValueError(
                    f"messages[{i}] must have role 'user'|'assistant'|'system' and a "
                    f"non-empty string 'content' (max {MAX_CONTENT_CHARS} chars).")
            cleaned.append({"role": role, "content": content})
        if cleaned[-1]["role"] != "user":
            raise ValueError("The last message must have role 'user'.")
        return cleaned

    if (not isinstance(message, str) or not message.strip()
            or len(message) > MAX_CONTENT_CHARS * MAX_MESSAGES):
        raise ValueError(
            "Provide a non-empty 'message' string, or a 'messages' array "
            f"(max {MAX_MESSAGES} entries).")
    return [{"role": "user", "content": message}]


def qwen_chat_impl(message: str | None = None,
                   messages: list[dict[str, str]] | None = None) -> str:
    """Core flow with automatic re-login on auth error:

    1. Normalizes messages.
    2. Runs up to 2 attempts:
       - Obtains token & cookies (forces fresh login on attempt > 0).
       - Establishes session and retrieves candidate chats.
       - Streams completions.
    3. If QwenAuthError occurs on attempt 0:
       - Automatically invalidates dead token.
       - Triggers re-login to acquire fresh tokens.
       - Seamlessly retries on attempt 1.
    """
    cleaned = _validate_messages(message, messages)
    err_detail = "Qwen request failed."

    for attempt in range(2):
        force = attempt > 0
        token, cookies = get_token(force_refresh=force)
        mode = "normal" if token else "guest"
        logger.info("Qwen mode for attempt %s: %s", attempt, mode)

        s = make_session(token, cookies)
        try:
            candidates = get_candidate_chats(s, mode)
            if not candidates:
                err_detail = "Qwen chat session initialization failed (no chat sessions available)."
                if attempt == 0:
                    invalidate_token(token)
                    continue
                break

            for chat_id in candidates[:5]:
                try:
                    ok, answer = send_message(s, chat_id, mode, cleaned)
                    if ok:
                        return answer
                except QwenChatBusyError:
                    logger.info("Chat %s busy (message in progress), trying next session...", chat_id)
                    continue

            err_detail = "Qwen returned an empty or failed completion across available sessions."
            if attempt == 0:
                invalidate_token(token)
                continue
            break
        except QwenAuthError as e:
            logger.warning("Qwen auth error on attempt %s: %s. Re-logging in...", attempt, e)
            invalidate_token(token)
            if attempt == 0:
                continue
            raise RuntimeError(
                f"Qwen authentication error ({e}). Re-login was attempted but failed. "
                "Please verify your EMAIL and PASSWORD credentials.")

    if mode == "guest":
        raise RuntimeError(
            f"{err_detail} Running in guest mode. If account login was expected, "
            "check EMAIL / PASSWORD in api/index.py or Vercel environment variables.")
    raise RuntimeError(
        f"{err_detail} Authentication retry completed. Please check your Qwen account credentials.")


# ----------------------------------------------------------------------------
# MCP server - Streamable HTTP, STATELESS (required for Vercel serverless)
# ----------------------------------------------------------------------------

mcp = FastMCP("qwen-chat", stateless_http=True)


@mcp.tool(
    name="qwen_chat",
    description=(
        "Send a user message to the configured Qwen backend (chat.qwen.ai) and "
        "return the generated response. Automatically refreshes tokens and re-logins "
        "if an authentication error occurs. Provide EITHER a single 'message' string, "
        'e.g. {"message": "Explain Python in simple words."}, OR a "messages" '
        "conversation array of role/content objects."
    ),
)
def qwen_chat_tool(message: str | None = None,
                   messages: list[dict[str, str]] | None = None) -> str:
    return qwen_chat_impl(message=message, messages=messages)


@mcp.tool(
    name="qwen_relogin",
    description=(
        "Force an immediate re-login to Qwen (chat.qwen.ai) to acquire fresh "
        "authentication tokens and cookies. Returns token validity and expiration."
    ),
)
def qwen_relogin_tool() -> str:
    """MCP tool to force a re-login and refresh token."""
    invalidate_token()
    token, _ = get_token(force_refresh=True)
    if token:
        exp = _decode_jwt_exp(token)
        return (f"Re-login successful! Acquired fresh token (expires at {time.ctime(exp)}). "
                f"Token preview: {token[:16]}...")
    return "Re-login failed. Please verify EMAIL and PASSWORD credentials."


mcp_app = mcp.streamable_http_app()  # serves POST/GET/DELETE at /mcp


# ----------------------------------------------------------------------------
# Optional API-key guard + health/relogin endpoints + final ASGI app
# ----------------------------------------------------------------------------

class APIKeyAuthMiddleware:
    """Pure-ASGI middleware: passes lifespan through, checks a static key on HTTP."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and MCP_API_KEY:
            headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                       for k, v in scope.get("headers", [])}
            auth = headers.get("authorization", "")
            api_key = headers.get("x-mcp-api-key", "")
            if auth != f"Bearer {MCP_API_KEY}" and api_key != MCP_API_KEY:
                await JSONResponse({"error": "unauthorized"}, status_code=401)(
                    scope, receive, send)
                return
        await self.app(scope, receive, send)


async def healthz(request):
    """Public health & authentication probe."""
    with _cache_lock:
        curr_token = _token_cache.get("token")
        exp = _token_cache.get("exp", 0.0)
        is_expired = _jwt_expired(curr_token) if curr_token else True

    return JSONResponse({
        "ok": True,
        "service": "qwen-chat-mcp",
        "model": MODEL,
        "auth_configured": bool(EMAIL and PASSWORD and "yahan_apna" not in PASSWORD),
        "account_email": EMAIL if EMAIL else None,
        "has_active_token": bool(curr_token and not is_expired),
        "token_expires_at": time.ctime(exp) if exp else None,
        "token_preview": (curr_token[:16] + "...") if curr_token else None,
        "mcp_endpoint": "/mcp",
        "relogin_endpoint": "/relogin",
        "api_key_required": bool(MCP_API_KEY),
    })


async def relogin_handler(request):
    """Force an immediate re-login and return fresh token status."""
    invalidate_token()
    token, _ = get_token(force_refresh=True)
    if token:
        exp = _decode_jwt_exp(token)
        return JSONResponse({
            "ok": True,
            "message": "Re-login successful! New token generated and cached.",
            "account_email": EMAIL,
            "token_preview": token[:16] + "...",
            "expires_at": time.ctime(exp),
            "exp_timestamp": exp,
        })
    return JSONResponse({
        "ok": False,
        "message": "Re-login failed. Please check EMAIL and PASSWORD.",
        "account_email": EMAIL,
    }, status_code=400)


_lifespan = getattr(mcp_app.router, "lifespan_context", getattr(mcp_app, "lifespan", None))

app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/relogin", relogin_handler, methods=["GET", "POST"]),
        Mount("/", app=APIKeyAuthMiddleware(mcp_app)),
    ],
    lifespan=_lifespan,
)
