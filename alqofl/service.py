"""Alqofl license verification as a local HTTP service.

``POST /api/verify`` verifies a license code centrally (useful when several
apps on one network want a single verification point). Issuing licenses stays
CLI-only — the private key is never loaded by the HTTP service.

Env: ``ALQOFL_PUBLIC_KEY`` overrides the public key path
(default ``<project>/keys/alqofl_ed25519_public.pem``).
"""

from __future__ import annotations

import os
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .http_base import BaseServiceHandler, build_server
from .license import verify_license


def public_key_path() -> Path:
    raw = os.environ.get("ALQOFL_PUBLIC_KEY", "").strip()
    return Path(raw) if raw else PROJECT_ROOT / "keys" / "alqofl_ed25519_public.pem"


def _verify_route(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    code = str(data.get("code") or "").strip()
    app_id = str(data.get("app_id") or "").strip()
    device_hash = str(data.get("device_hash") or "").strip()
    if not code or not app_id or not device_hash:
        return 400, {"ok": False, "error": "missing 'code', 'app_id' or 'device_hash'"}
    key_path = public_key_path()
    if not key_path.exists():
        return 503, {"ok": False, "error": f"public key not found: {key_path}"}
    result = verify_license(code, public_key=key_path, expected_app_id=app_id, device_hash=device_hash)
    return 200, {"ok": True, **result.to_dict()}


class Handler(BaseServiceHandler):
    post_routes = {"/api/verify": staticmethod(_verify_route)}


def create_server(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    return build_server(Handler, host=host, port=port)


def run_server(host: str | None = None, port: int | None = None) -> None:
    from .version import __version__

    server = create_server(host=host, port=port)
    print(f"alqofl service v{__version__}: http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
