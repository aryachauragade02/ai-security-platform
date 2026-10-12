"""Storage layer.

Uses Supabase (Postgres) through its REST API when SUPABASE_URL and
SUPABASE_SERVICE_KEY are set. Otherwise it falls back to an in-memory store so
the project still runs locally and in tests (data is lost on restart).
"""
import logging
import threading
import uuid
from datetime import datetime, timezone
from functools import lru_cache

import httpx

from .config import settings

log = logging.getLogger("store")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fmt(value) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


class MemoryStore:
    name = "memory"

    def __init__(self) -> None:
        self._tables: dict[str, list[dict]] = {}
        self._lock = threading.Lock()

    def insert(self, table: str, row: dict) -> dict:
        record = {"id": str(uuid.uuid4()), "created_at": _now(), **row}
        with self._lock:
            self._tables.setdefault(table, []).append(record)
        return dict(record)

    def insert_many(self, table: str, rows: list[dict]) -> list[dict]:
        return [self.insert(table, r) for r in rows]

    def select(self, table: str, eq: dict | None = None, limit: int = 100, newest_first: bool = True) -> list[dict]:
        with self._lock:
            rows = list(self._tables.get(table, []))
        for key, value in (eq or {}).items():
            rows = [r for r in rows if r.get(key) == value]
        rows.sort(key=lambda r: r["created_at"], reverse=newest_first)
        return [dict(r) for r in rows[:limit]]

    def update(self, table: str, eq: dict, values: dict) -> list[dict]:
        updated = []
        with self._lock:
            for row in self._tables.get(table, []):
                if all(row.get(k) == v for k, v in eq.items()):
                    row.update(values)
                    updated.append(dict(row))
        return updated


class SupabaseStore:
    name = "supabase"

    def __init__(self, url: str, key: str) -> None:
        self.base = url.rstrip("/") + "/rest/v1"
        self.client = httpx.Client(
            timeout=15,
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
        )

    @staticmethod
    def _eq(eq: dict | None) -> dict:
        return {k: f"eq.{_fmt(v)}" for k, v in (eq or {}).items()}

    def insert(self, table: str, row: dict) -> dict:
        r = self.client.post(f"{self.base}/{table}", json=row, headers={"Prefer": "return=representation"})
        r.raise_for_status()
        return r.json()[0]

    def insert_many(self, table: str, rows: list[dict]) -> list[dict]:
        if not rows:
            return []
        r = self.client.post(f"{self.base}/{table}", json=rows, headers={"Prefer": "return=representation"})
        r.raise_for_status()
        return r.json()

    def select(self, table: str, eq: dict | None = None, limit: int = 100, newest_first: bool = True) -> list[dict]:
        params = {
            "select": "*",
            "order": f"created_at.{'desc' if newest_first else 'asc'}",
            "limit": str(limit),
            **self._eq(eq),
        }
        r = self.client.get(f"{self.base}/{table}", params=params)
        r.raise_for_status()
        return r.json()

    def update(self, table: str, eq: dict, values: dict) -> list[dict]:
        r = self.client.patch(
            f"{self.base}/{table}",
            params=self._eq(eq),
            json=values,
            headers={"Prefer": "return=representation"},
        )
        r.raise_for_status()
        return r.json()


@lru_cache(maxsize=1)
def get_store():
    if settings.supabase_url and settings.supabase_service_key:
        log.info("Using Supabase store")
        return SupabaseStore(settings.supabase_url, settings.supabase_service_key)
    log.warning("SUPABASE_URL / SUPABASE_SERVICE_KEY not set: using in-memory store")
    return MemoryStore()
