"""Caché de resultados e historial de consultas en SQLite."""
import json
import sqlite3
import time
from dataclasses import asdict

from ioc.sources import AbuseResult, VTResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    ioc        TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,        -- resultados en JSON
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    chat_id    INTEGER,
    ioc        TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,
    verdict    TEXT NOT NULL
);
"""


class Cache:
    def __init__(self, path: str = "ioc_cache.db", ttl_hours: float = 24, clock=time.time):
        self.ttl = ttl_hours * 3600
        self.clock = clock
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def get(self, ioc: str) -> tuple[VTResult | None, AbuseResult | None, VTResult | None] | None:
        """Devuelve (vt, abuse, domain_vt) si hay un resultado vigente; si no, None."""
        # Consultas parametrizadas (?): nunca concatenar texto del usuario en SQL
        row = self.db.execute(
            "SELECT payload, created_at FROM cache WHERE ioc = ?", (ioc,)
        ).fetchone()
        if row is None:
            return None
        data = json.loads(row[0])
        ttl = data.get("ttl", self.ttl)     # cada resultado puede tener su propio TTL
        if self.clock() - row[1] > ttl:
            return None
        vt = VTResult(**data["vt"]) if data["vt"] else None
        abuse = AbuseResult(**data["abuse"]) if data["abuse"] else None
        domain_vt = VTResult(**data["domain_vt"]) if data.get("domain_vt") else None
        return vt, abuse, domain_vt

    def set(self, ioc: str, vt: VTResult | None, abuse: AbuseResult | None,
            domain_vt: VTResult | None = None, ttl_hours: float | None = None) -> None:
        payload = json.dumps({
            "vt": asdict(vt) if vt else None,
            "abuse": asdict(abuse) if abuse else None,
            "domain_vt": asdict(domain_vt) if domain_vt else None,
            "ttl": ttl_hours * 3600 if ttl_hours is not None else self.ttl,
        })
        self.db.execute(
            "INSERT OR REPLACE INTO cache (ioc, payload, created_at) VALUES (?, ?, ?)",
            (ioc, payload, self.clock()),
        )
        self.db.commit()

    def log(self, ioc: str, ioc_type: str, verdict: str, chat_id: int | None = None) -> None:
        self.db.execute(
            "INSERT INTO history (ts, chat_id, ioc, ioc_type, verdict) VALUES (?, ?, ?, ?, ?)",
            (self.clock(), chat_id, ioc, ioc_type, verdict),
        )
        self.db.commit()

    def history(self, limit: int = 10) -> list[tuple]:
        return self.db.execute(
            "SELECT ts, ioc, ioc_type, verdict FROM history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def close(self) -> None:
        self.db.close()
