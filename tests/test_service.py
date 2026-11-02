"""Prueba del flujo completo con clientes falsos (sin internet)."""
import asyncio

import pytest

from ioc.cache import Cache
from ioc.service import Analyzer, url_host
from ioc.sources import AbuseResult, RateLimitError, VTResult
from ioc.verdict import Verdict


class FakeVT:
    """Devuelve un resultado por IOC (`results`) o uno por defecto; cuenta las llamadas."""

    def __init__(self, default=None, error=None, results=None):
        self.default, self.error, self.results = default, error, results or {}
        self.calls = []

    async def lookup(self, ioc):
        value = getattr(ioc, "value", ioc)   # VT recibe ParsedIOC; AbuseIPDB, un str
        self.calls.append(value)
        if self.error:
            raise self.error
        return self.results.get(value, self.default)


def make(tmp_path, vt=None, abuse=None):
    return Analyzer(vt or FakeVT(VTResult(found=True)), abuse or FakeVT(), Cache(tmp_path / "t.db"))


def test_segunda_consulta_sale_de_cache(tmp_path):
    vt = FakeVT(VTResult(found=True, malicious=5))
    an = make(tmp_path, vt=vt)
    r1 = asyncio.run(an.analyze("malo[.]com"))
    r2 = asyncio.run(an.analyze("MALO.COM"))         # normalizado: mismo IOC
    assert r1.assessment.verdict is Verdict.MALICIOUS
    assert r2.from_cache and len(vt.calls) == 1


def test_ip_privada_no_consulta(tmp_path):
    vt = FakeVT()
    r = asyncio.run(make(tmp_path, vt=vt).analyze("10.0.2.15"))
    assert r.skipped and vt.calls == []


def test_dominio_no_consulta_abuseipdb(tmp_path):
    ab = FakeVT()
    asyncio.run(make(tmp_path, abuse=ab).analyze("google.com"))
    assert ab.calls == []


def test_error_no_se_guarda_en_cache(tmp_path):
    vt = FakeVT(error=RateLimitError("VirusTotal", 30))
    ab = FakeVT(AbuseResult(80, 5, "CN", "i", "u", False, "l"))
    an = make(tmp_path, vt=vt, abuse=ab)
    r = asyncio.run(an.analyze("1.2.3.4"))
    assert r.errors and r.assessment.verdict is Verdict.MALICIOUS   # AbuseIPDB sí respondió
    assert an.cache.get("1.2.3.4") is None


def test_ioc_invalido_lanza_valueerror(tmp_path):
    with pytest.raises(ValueError):
        asyncio.run(make(tmp_path).analyze("hola"))


# ---------- URL desconocida -> consulta del dominio ----------

URL = "https://best.aliexpress.com/?aff_trace_key=abc123"


def test_url_desconocida_consulta_el_dominio(tmp_path):
    vt = FakeVT(results={URL: VTResult(found=False),
                         "best.aliexpress.com": VTResult(found=True, harmless=60)})
    an = make(tmp_path, vt=vt)
    r = asyncio.run(an.analyze(URL))
    assert vt.calls == [URL, "best.aliexpress.com"]
    assert r.assessment.verdict is Verdict.UNKNOWN          # dominio limpio no limpia la URL
    assert r.domain_vt.found


def test_url_conocida_no_consulta_el_dominio(tmp_path):
    vt = FakeVT(VTResult(found=True, harmless=60))
    asyncio.run(make(tmp_path, vt=vt).analyze("http://google.com"))
    assert len(vt.calls) == 1                                # ahorra cuota


def test_url_desconocida_queda_en_cache_con_ttl_corto(tmp_path):
    t = [0.0]
    vt = FakeVT(VTResult(found=False))
    an = Analyzer(vt, FakeVT(), Cache(tmp_path / "t.db", clock=lambda: t[0]))
    asyncio.run(an.analyze("http://nuevo.com/x"))
    t[0] = 1800                                              # 30 min: sigue en caché
    assert an.cache.get("http://nuevo.com/x") is not None
    t[0] = 3700                                              # > 1 h: caducó
    assert an.cache.get("http://nuevo.com/x") is None


def test_url_host():
    assert url_host("https://Best.AliExpress.com/x?y=1").value == "best.aliexpress.com"
    assert url_host("http://8.8.8.8/x").value == "8.8.8.8"
    assert url_host("http://192.168.1.1/admin") is None      # IP privada: no se consulta
