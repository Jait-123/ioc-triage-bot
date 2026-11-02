"""Clientes de VirusTotal (API v3) y AbuseIPDB (API v2)."""
import base64
import time
from collections import deque
from dataclasses import dataclass

import httpx

from ioc.parser import IOCType, ParsedIOC

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 15.0  # segundos máximos esperando a una API


# ---------- Errores ----------

class SourceError(Exception):
    """Fallo al consultar una fuente (clave inválida, caída, respuesta rara)."""


class RateLimitError(SourceError):
    """Se alcanzó el límite de consultas; retry_after = segundos a esperar."""

    def __init__(self, source: str, retry_after: int):
        super().__init__(f"{source}: límite de consultas alcanzado, reintenta en {retry_after} s")
        self.retry_after = retry_after


# ---------- Resultados ----------

@dataclass
class VTResult:
    found: bool            # False = VirusTotal no conoce el IOC (404)
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    link: str | None = None


@dataclass
class AbuseResult:
    score: int             # abuseConfidenceScore, de 0 a 100
    total_reports: int
    country: str | None
    isp: str | None
    usage_type: str | None
    is_whitelisted: bool | None
    link: str


# ---------- Control de ritmo ----------

class RateLimiter:
    """Ventana deslizante: como máximo `max_calls` llamadas cada `period` segundos."""

    def __init__(self, max_calls: int, period: float, clock=time.monotonic):
        self.max_calls = max_calls
        self.period = period
        self.clock = clock          # inyectable para poder probarlo sin esperar
        self.calls: deque[float] = deque()

    def acquire(self) -> int:
        """Registra una llamada y devuelve 0, o devuelve los segundos que faltan si no hay cupo."""
        now = self.clock()
        while self.calls and now - self.calls[0] >= self.period:
            self.calls.popleft()    # descartar llamadas fuera de la ventana
        if len(self.calls) >= self.max_calls:
            return int(self.period - (now - self.calls[0])) + 1
        self.calls.append(now)
        return 0


# ---------- VirusTotal ----------

# tipo de IOC -> (ruta en la API, ruta en la web de VirusTotal)
VT_PATHS = {
    IOCType.IP: ("ip_addresses", "ip-address"),
    IOCType.DOMAIN: ("domains", "domain"),
    IOCType.URL: ("urls", "url"),
    IOCType.MD5: ("files", "file"),
    IOCType.SHA1: ("files", "file"),
    IOCType.SHA256: ("files", "file"),
}


def vt_url_id(url: str) -> str:
    """VirusTotal identifica una URL por su base64 'url-safe' sin el relleno '='."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalClient:
    def __init__(self, api_key: str, http: httpx.AsyncClient, limiter: RateLimiter | None = None):
        self.http = http
        self.headers = {"x-apikey": api_key}
        self.limiter = limiter or RateLimiter(max_calls=4, period=60)  # API pública: 4/min

    async def lookup(self, ioc: ParsedIOC) -> VTResult:
        api_path, gui_path = VT_PATHS[ioc.type]
        ident = vt_url_id(ioc.value) if ioc.type is IOCType.URL else ioc.value

        # Frenamos ANTES de llamar: no gastamos una petición que sabemos que fallará
        wait = self.limiter.acquire()
        if wait:
            raise RateLimitError("VirusTotal", wait)

        try:
            r = await self.http.get(f"{VT_BASE}/{api_path}/{ident}",
                                    headers=self.headers, timeout=TIMEOUT)
        except httpx.HTTPError as e:
            raise SourceError(f"VirusTotal: error de conexión ({type(e).__name__})") from e

        if r.status_code == 404:
            return VTResult(found=False)
        if r.status_code == 429:
            raise RateLimitError("VirusTotal", 60)
        if r.status_code == 401:
            raise SourceError("VirusTotal: API key inválida")
        if r.status_code != 200:
            raise SourceError(f"VirusTotal: respuesta inesperada (HTTP {r.status_code})")

        data = r.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        return VTResult(
            found=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            link=f"https://www.virustotal.com/gui/{gui_path}/{data.get('id', ident)}",
        )


# ---------- AbuseIPDB ----------

class AbuseIPDBClient:
    def __init__(self, api_key: str, http: httpx.AsyncClient):
        self.http = http
        self.headers = {"Key": api_key, "Accept": "application/json"}

    async def lookup(self, ip: str) -> AbuseResult:
        try:
            r = await self.http.get(ABUSE_URL, headers=self.headers, timeout=TIMEOUT,
                                    params={"ipAddress": ip, "maxAgeInDays": 90})
        except httpx.HTTPError as e:
            raise SourceError(f"AbuseIPDB: error de conexión ({type(e).__name__})") from e

        if r.status_code == 429:
            raise RateLimitError("AbuseIPDB", int(r.headers.get("Retry-After", 3600)))
        if r.status_code == 401:
            raise SourceError("AbuseIPDB: API key inválida")
        if r.status_code != 200:
            raise SourceError(f"AbuseIPDB: respuesta inesperada (HTTP {r.status_code})")

        d = r.json()["data"]
        return AbuseResult(
            score=d.get("abuseConfidenceScore", 0),
            total_reports=d.get("totalReports", 0),
            country=d.get("countryCode"),
            isp=d.get("isp"),
            usage_type=d.get("usageType"),
            is_whitelisted=d.get("isWhitelisted"),
            link=f"https://www.abuseipdb.com/check/{ip}",
        )