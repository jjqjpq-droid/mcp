"""Vercel function for the MCP endpoint (POST/GET/DELETE /mcp).

Vercel's Python runtime now applies rewrites to the request path seen by
user code, so a catch-all rewrite to api/index.py makes every route arrive
as "/api/index" and the app cannot tell /mcp apart from /healthz.
Filesystem routing has no such rewrite: each clean path maps to its own
function file, and the app always sees the original path.

This thin wrapper loads the shared Starlette `app` from api/index.py by
explicit file path so the import works regardless of sys.path setup.
"""

import importlib.util as _importlib_util
import os as _os

_core_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "index.py")
_spec = _importlib_util.spec_from_file_location("_qwen_core", _core_path)
_core = _importlib_util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

app = _core.app
