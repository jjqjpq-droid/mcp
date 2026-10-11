"""Vercel function for the health endpoint (GET /healthz).

Thin wrapper around the shared Starlette `app` in api/index.py — see
api/mcp.py for why each path is its own function file.
"""

import importlib.util as _importlib_util
import os as _os

_core_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "index.py")
_spec = _importlib_util.spec_from_file_location("_qwen_core", _core_path)
_core = _importlib_util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

app = _core.app
