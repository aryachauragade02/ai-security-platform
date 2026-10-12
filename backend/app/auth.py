import hmac

from fastapi import Header, HTTPException

from .config import settings


def _check(expected: str, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(expected, supplied)


def require_gateway_key(x_gateway_key: str | None = Header(default=None)) -> str:
    """If GATEWAY_API_KEY is set, callers must send it in the x-gateway-key header."""
    if settings.gateway_api_key and not _check(settings.gateway_api_key, x_gateway_key):
        raise HTTPException(status_code=401, detail="Missing or wrong x-gateway-key")
    return x_gateway_key or ""


def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
    """If ADMIN_API_KEY is set, admin actions need it in the x-admin-key header."""
    if settings.admin_api_key and not _check(settings.admin_api_key, x_admin_key):
        raise HTTPException(status_code=401, detail="Admin key required (x-admin-key)")
