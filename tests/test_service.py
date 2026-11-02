"""Prueba del flujo completo con clientes falsos (sin internet)."""
import asyncio

import pytest

from ioc.cache import Cache
from ioc.service import Analyzer
from ioc.sources import AbuseResult, RateLimitError, VTResult
from ioc.verdict import Verdict


class FakeVT:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, 0

    async def lookup(self, ioc):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


class FakeAbuse(FakeVT):
    async def lookup(self, ip):
        return await super().lookup(ip)


def make(tmp_path, vt=None, abuse=None):
    return Analyzer(vt or FakeVT(VTResult(found=True)), abuse or FakeAbuse(), Cache(tmp_path / "t.db"))


def test_segunda_consulta_sale_de_cache(tmp_path):
    vt = FakeVT(VTResult(found=True, malicious=5))
    an = make(tmp_path, vt=vt)
    r1 = asyncio.run(an.analyze("malo[.]com"))
    r2 = asyncio.run(an.analyze("MALO.COM"))         # normalizado: mismo IOC
    assert r1.assessment.verdict is Verdict.MALICIOUS
    assert r2.from_cache and vt.calls == 1


def test_ip_privada_no_consulta(tmp_path):
    vt = FakeVT()
    r = asyncio.run(make(tmp_path, vt=vt).analyze("10.0.2.15"))
    assert r.skipped and vt.calls == 0


def test_dominio_no_consulta_abuseipdb(tmp_path):
    ab = FakeAbuse()
    asyncio.run(make(tmp_path, abuse=ab).analyze("google.com"))
    assert ab.calls == 0


def test_error_no_se_guarda_en_cache(tmp_path):
    vt = FakeVT(error=RateLimitError("VirusTotal", 30))
    ab = FakeAbuse(AbuseResult(80, 5, "CN", "i", "u", False, "l"))
    an = make(tmp_path, vt=vt, abuse=ab)
    r = asyncio.run(an.analyze("1.2.3.4"))
    assert r.errors and r.assessment.verdict is Verdict.MALICIOUS   # AbuseIPDB sí respondió
    assert an.cache.get("1.2.3.4") is None


def test_ioc_invalido_lanza_valueerror(tmp_path):
    with pytest.raises(ValueError):
        asyncio.run(make(tmp_path).analyze("hola"))