"""Tests de los clientes SIN internet: httpx.MockTransport simula las respuestas de las APIs."""
import asyncio

import httpx
import pytest

from ioc.parser import parse_ioc
from ioc.sources import (AbuseIPDBClient, RateLimiter, RateLimitError, SourceError,
                         VirusTotalClient, vt_url_id)

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def mock_http(handler):
    """Cliente HTTP falso: cada petición la responde `handler` en vez de internet."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


# ---------- RateLimiter ----------

def test_rate_limiter_bloquea_la_quinta_llamada():
    t = [0.0]
    lim = RateLimiter(max_calls=4, period=60, clock=lambda: t[0])
    assert [lim.acquire() for _ in range(4)] == [0, 0, 0, 0]
    assert lim.acquire() > 0           # 5.ª llamada en el mismo minuto: bloqueada
    t[0] = 61.0                        # "pasa" un minuto
    assert lim.acquire() == 0


# ---------- VirusTotal ----------

def test_vt_url_id():
    assert vt_url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"


def test_vt_parsea_resultado_y_envia_api_key():
    def handler(req):
        assert req.url.path == f"/api/v3/files/{EICAR_MD5}"
        assert req.headers["x-apikey"] == "clave-falsa"
        return httpx.Response(200, json={"data": {"id": "abc", "attributes": {
            "last_analysis_stats": {"malicious": 60, "suspicious": 1,
                                    "harmless": 0, "undetected": 10}}}})

    async def go():
        async with mock_http(handler) as http:
            return await VirusTotalClient("clave-falsa", http).lookup(parse_ioc(EICAR_MD5))

    res = run(go())
    assert res.found and res.malicious == 60 and res.undetected == 10
    assert res.link == "https://www.virustotal.com/gui/file/abc"


def test_vt_404_no_encontrado():
    async def go():
        async with mock_http(lambda req: httpx.Response(404)) as http:
            return await VirusTotalClient("k", http).lookup(parse_ioc("8.8.8.8"))
    assert run(go()).found is False


@pytest.mark.parametrize("status, error", [(429, RateLimitError), (401, SourceError), (500, SourceError)])
def test_vt_errores_http(status, error):
    async def go():
        async with mock_http(lambda req: httpx.Response(status)) as http:
            await VirusTotalClient("k", http).lookup(parse_ioc("google.com"))
    with pytest.raises(error):
        run(go())


def test_vt_no_llama_a_la_api_si_no_hay_cupo():
    llamadas = []

    def handler(req):
        llamadas.append(req)
        return httpx.Response(404)

    async def go():
        async with mock_http(handler) as http:
            vt = VirusTotalClient("k", http, limiter=RateLimiter(max_calls=1, period=60))
            await vt.lookup(parse_ioc("8.8.8.8"))
            await vt.lookup(parse_ioc("1.1.1.1"))   # esta debe bloquearse localmente

    with pytest.raises(RateLimitError):
        run(go())
    assert len(llamadas) == 1


# ---------- AbuseIPDB ----------

def test_abuse_parsea_resultado():
    def handler(req):
        assert req.url.params["ipAddress"] == "1.2.3.4"
        assert req.headers["Key"] == "k"
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": 87, "totalReports": 120, "countryCode": "CN",
            "isp": "Ejemplo ISP", "usageType": "Data Center", "isWhitelisted": False}})

    async def go():
        async with mock_http(handler) as http:
            return await AbuseIPDBClient("k", http).lookup("1.2.3.4")

    res = run(go())
    assert res.score == 87 and res.total_reports == 120 and res.country == "CN"


def test_abuse_429_usa_retry_after():
    async def go():
        async with mock_http(lambda req: httpx.Response(429, headers={"Retry-After": "120"})) as http:
            await AbuseIPDBClient("k", http).lookup("1.2.3.4")
    with pytest.raises(RateLimitError) as exc:
        run(go())
    assert exc.value.retry_after == 120