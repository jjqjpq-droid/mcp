#!/usr/bin/env python3
"""
Qwen Chat Remote MCP Server (Vercel serverless)
================================================

Architecture:
    Claude Web -> Custom Connector -> this MCP server (Vercel)
        -> Qwen (chat.qwen.ai) -> response back to Claude Web

Converted from auto.py:
  * The interactive CLI loop (`while True: input(...)`) is REMOVED.
  * The functionality is exposed as ONE MCP tool: `qwen_chat`.
  * Credentials are hard-coded below (auto.py style). Vercel env vars
    (QWEN_EMAIL etc.) are used ONLY as fallback when the code values are blank.
  * No local `qwen_session.json`: the Qwen token is cached in warm-instance
    memory with automatic re-login on JWT expiry; guest fallback preserved.

Endpoints:
    MCP:    POST https://<project>.vercel.app/mcp   (Streamable HTTP, stateless)
    Health: GET  https://<project>.vercel.app/healthz
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

MCP_API_KEY = os.environ.get("MCP_API_KEY", "").strip()   # OPTIONAL - see README (Claude Web cannot send custom headers)
QWEN_TOKEN = os.environ.get("QWEN_TOKEN", "").strip()     # OPTIONAL pre-seeded Qwen JWT

HEADERS = {
    "source": "app",
    "X-Platform": "android",
    "Accept-Language": "en-US",
    "Accept-Charset": "UTF-8",
    "User-Agent": ("Dalvik/2.1.0 (Linux; U; Android 16; V2502 Build/BP2A.250605.031.A3_V000L1) "
                   "AliApp(QWENCHAT/2.4.0) AppType/Release AplusBridgeLite"),
}

MAX_MESSAGES = 50
MAX_CONTENT_CHARS = 20000  # per message


# ----------------------------------------------------------------------------
# Token cache (in-memory, per warm serverless instance) - replaces qwen_session.json
# ----------------------------------------------------------------------------

_cache_lock = threading.Lock()
_token_cache: dict[str, Any] = {"token": None, "exp": 0.0}


def _decode_jwt_exp(token: str) -> float:
    """Decode JWT exp claim WITHOUT verifying signature (same idea as auto.py)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return float(data.get("exp", 0) or 0)
    except Exception:
        return 0.0


def _jwt_expired(token: str) -> bool:
    return time.time() > _decode_jwt_exp(token) - 300  # 5 min safety margin, same as auto.py


def extract_token(resp: requests.Response):
    """Token ko response se kahin se bhi nikalo (same logic as auto.py)."""
    try:
        body = resp.json()
    except Exception:
        body = {}
    data = body.get("data") or {}
    for key in ("token", "access_token", "jwt"):
        if isinstance(data, dict) and data.get(key):
            return data[key]
    for c in resp.cookies:  # set-cookie se
        if c.name == "token":
            return c.value
    txt = resp.text  # fallback: poora body dekho
    if "eyJ" in txt:
        i = txt.find("eyJ")
        j = txt.find('"', i)
        if j > i:
            return txt[i:j]
    return None


def login() -> str | None:
    """Email+password se naya token lo. SHA256 hash bhejo (same as auto.py)."""
    if not EMAIL or not PASSWORD or "yahan_apna" in PASSWORD:
        return None
    hashed = hashlib.sha256(PASSWORD.encode()).hexdigest()
    try:
        r = requests.post(
            f"{BASE}/api/v2/auths/signin",
            headers={**HEADERS, "Accept": "application/json",
                     "Content-Type": "application/json"},
            cookies={"acw_tc": ACW_TC, "x-ap": "ap-southeast-1"},
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
        logger.info("Qwen login OK")
    else:
        logger.warning("Qwen login failed: no token found in signin response")
    return token


def get_token() -> str | None:
    """Valid token do: warm cache -> env-seeded token -> fresh login.

    Auto re-login on expiry (same behavior as auto.py's get_token).
    Returns None when credentials are not configured / login fails,
    which triggers the guest fallback in qwen_chat_impl.
    """
    with _cache_lock:
        tok = _token_cache["token"]
        if tok and not _jwt_expired(tok):
            return tok
        if QWEN_TOKEN and not _jwt_expired(QWEN_TOKEN):
            _token_cache["token"] = QWEN_TOKEN
            _token_cache["exp"] = _decode_jwt_exp(QWEN_TOKEN)
            return QWEN_TOKEN
        fresh = login()
        if fresh:
            _token_cache["token"] = fresh
            _token_cache["exp"] = _decode_jwt_exp(fresh)
            return fresh
        _token_cache["token"] = None
        _token_cache["exp"] = 0.0
        return None


# ----------------------------------------------------------------------------
# Qwen HTTP client - identical endpoints/payloads to auto.py
# ----------------------------------------------------------------------------

def make_session(token: str | None = None) -> requests.Session:
    s = requests.Session()
    if ACW_TC:
        s.cookies.set("acw_tc", ACW_TC, domain="chat.qwen.ai")
    s.cookies.set("x-ap", "ap-southeast-1", domain="chat.qwen.ai")
    if token:
        s.cookies.set("token", token, domain="chat.qwen.ai")
        s.headers["Authorization"] = f"Bearer {token}"
    s.headers.update(HEADERS)
    return s


def new_chat(session: requests.Session, mode: str) -> str | None:
    r = session.post(
        f"{BASE}/api/v2/chats/new",
        headers={"Accept": "application/json"},
        json={"chat_mode": mode, "project_id": ""},
        timeout=20,
    )
    try:
        body = r.json()
    except Exception:
        return None
    if r.status_code == 200 and body.get("success"):
        return body["data"]["id"]
    return None


def send_message(session: requests.Session, chat_id: str, mode: str,
                 messages: list[dict[str, str]]) -> tuple[bool, str]:
    """SSE stream collect karke FINAL combined answer return karo: (ok, answer).

    Chunk-parsing logic is identical to auto.py; the only difference is we
    accumulate into a string instead of printing, because an MCP tool result
    must contain the complete final answer.
    """
    # Qwen payload (auto.py jaisa). History messages plain role/content hain;
    # wrapper fields (chat_type/feature_config/models/...) sirf last user
    # message par - bilkul auto.py ke single-message payload ke barabar.
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
                     "Content-Type": "application/json; charset=UTF-8", "app_waf": APP_WAF},
            json=payload, stream=True, timeout=180,
        ) as r:
            if r.status_code != 200:
                logger.warning("Qwen completions returned HTTP %s", r.status_code)
                return False, ""
            answer = ""
            for line in r.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data:
                    continue
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if "response.created" in obj:
                    continue
                for choice in obj.get("choices", []):
                    delta = choice.get("delta", {})
                    if delta.get("phase") == "answer":
                        if delta.get("content"):
                            answer += delta["content"]
                        if delta.get("status") == "finished":
                            return bool(answer), answer
            return bool(answer), answer
    except requests.RequestException as e:
        logger.warning("Qwen completions request error: %s", type(e).__name__)
        return False, ""


def _validate_messages(message, messages) -> list[dict[str, str]]:
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
    """Core flow (mirrors auto.py main loop, minus the CLI):

    validate -> get token (auto re-login on expiry) -> new chat
    -> send message(s) -> collect streamed answer -> return final text.
    Falls back to guest mode when login is unavailable/fails.
    """
    cleaned = _validate_messages(message, messages)

    token = get_token()
    mode = "token" if token else "guest"
    logger.info("Qwen mode for this call: %s", mode)

    err_detail = "Qwen request failed."
    for attempt in range(2):
        s = make_session(token)
        chat_id = new_chat(s, "normal" if mode == "token" else "guest")
        if not chat_id:
            err_detail = "Qwen chat creation failed."
            if mode == "token" and attempt == 0:
                fresh = login()  # token stale ho sakta hai - force re-login (auto refresh)
                if fresh:
                    token = fresh
                    continue
            break
        ok, answer = send_message(s, chat_id, mode, cleaned)
        if ok:
            return answer
        err_detail = "Qwen returned an empty or failed completion."
        if mode == "token" and attempt == 0:
            fresh = login()
            if fresh:
                token = fresh
                continue
        break

    # Guest fallback bhi fail ho gaya / ya login hi nahi hua
    if mode == "guest":
        raise RuntimeError(
            err_detail + " Running in guest mode. If account login was expected, "
            "check the EMAIL / PASSWORD / ACW_TC / APP_WAF values at the top of api/index.py.")
    raise RuntimeError(
        err_detail + " Token authentication and guest fallback both failed; "
        "check Qwen credentials and WAF cookies.")


# ----------------------------------------------------------------------------
# MCP server - Streamable HTTP, STATELESS (required for Vercel serverless)
# ----------------------------------------------------------------------------

mcp = FastMCP("qwen-chat", stateless_http=True)


@mcp.tool(
    name="qwen_chat",
    description=(
        "Send a user message to the configured Qwen backend (chat.qwen.ai) and "
        "return the generated response. Provide EITHER a single 'message' string, "
        'e.g. {"message": "Explain Python in simple words."}, OR a "messages" '
        "conversation array of role/content objects (roles: user, assistant, "
        "system; max 50 entries; the last message must have role 'user') to "
        "continue an existing conversation. Returns the complete generated answer."
    ),
)
def qwen_chat_tool(message: str | None = None,
                   messages: list[dict[str, str]] | None = None) -> str:
    return qwen_chat_impl(message=message, messages=messages)


mcp_app = mcp.streamable_http_app()  # serves POST/GET/DELETE at /mcp


# ----------------------------------------------------------------------------
# Optional API-key guard + health endpoint + final ASGI app
# ----------------------------------------------------------------------------

class APIKeyAuthMiddleware:
    """Pure-ASGI middleware: passes lifespan through, checks a static key on HTTP.

    IMPORTANT: Claude Web custom connectors currently cannot send custom
    HTTP headers (OAuth only), so if you want Claude Web to connect, leave
    MCP_API_KEY UNSET. This guard is for direct API/inspector access and
    non-Claude clients.
    """

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
    """Public health/config probe - never reveals secrets."""
    return JSONResponse({
        "ok": True,
        "service": "qwen-chat-mcp",
        "model": MODEL,
        "auth_mode": "qwen-account + guest fallback" if (EMAIL and PASSWORD) else "guest only",
        "mcp_endpoint": "/mcp",
        "api_key_required": bool(MCP_API_KEY),
    })


app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Mount("/", app=APIKeyAuthMiddleware(mcp_app)),
    ],
    lifespan=mcp_app.lifespan,  # REQUIRED for streamable-http session manager
)
