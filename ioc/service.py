"""Orquesta el análisis completo: parser -> caché -> fuentes -> veredicto -> historial."""
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ioc.cache import Cache
from ioc.parser import IOCType, ParsedIOC, is_public_ip, parse_ioc
from ioc.sources import (AbuseIPDBClient, AbuseResult, SourceError, VirusTotalClient,
                         VTResult)
from ioc.verdict import Assessment, Verdict, evaluate

# Un "desconocido" caduca antes: VirusTotal puede analizar el IOC en cualquier momento
UNKNOWN_TTL_HOURS = 1


@dataclass
class Report:
    ioc: ParsedIOC
    assessment: Assessment | None = None
    vt: VTResult | None = None
    abuse: AbuseResult | None = None
    domain: ParsedIOC | None = None      # dominio de la URL, si se consultó
    domain_vt: VTResult | None = None
    errors: list[str] = field(default_factory=list)
    from_cache: bool = False
    skipped: str | None = None   # motivo por el que no se consultó


def url_host(url: str) -> ParsedIOC | None:
    """Extrae el host de una URL como IOC (dominio o IP pública)."""
    try:
        host = parse_ioc(urlparse(url).hostname or "")
    except ValueError:
        return None
    if host.type is IOCType.IP and not is_public_ip(host.value):
        return None
    return host


class Analyzer:
    def __init__(self, vt: VirusTotalClient, abuse: AbuseIPDBClient, cache: Cache):
        self.vt = vt
        self.abuse = abuse
        self.cache = cache

    async def analyze(self, raw: str, chat_id: int | None = None) -> Report:
        """Lanza ValueError si el texto no es un IOC válido."""
        ioc = parse_ioc(raw)
        report = Report(ioc)

        if ioc.type is IOCType.IP and not is_public_ip(ioc.value):
            report.skipped = "IP privada o reservada: no tiene reputación pública."
            return report

        if ioc.type is IOCType.URL:
            report.domain = url_host(ioc.value)

        cached = self.cache.get(ioc.value)
        if cached:
            report.vt, report.abuse, report.domain_vt = cached
            report.from_cache = True
        else:
            await self._lookup(report)

        if report.vt or report.abuse:
            report.assessment = evaluate(report.vt, report.abuse, report.domain_vt)
            if not report.from_cache and not report.errors:
                # Solo se guardan resultados completos: un error no debe quedar en caché
                ttl = UNKNOWN_TTL_HOURS if report.assessment.verdict is Verdict.UNKNOWN else None
                self.cache.set(ioc.value, report.vt, report.abuse, report.domain_vt, ttl)
            self.cache.log(ioc.value, ioc.type.value, report.assessment.verdict.name, chat_id)
        return report

    async def _lookup(self, report: Report) -> None:
        ioc = report.ioc
        try:
            report.vt = await self.vt.lookup(ioc)
        except SourceError as e:
            report.errors.append(str(e))

        if ioc.type is IOCType.IP:
            try:
                report.abuse = await self.abuse.lookup(ioc.value)
            except SourceError as e:
                report.errors.append(str(e))

        # URL desconocida -> consultar su dominio como contexto (1 petición extra)
        if ioc.type is IOCType.URL and report.vt and not report.vt.found and report.domain:
            try:
                report.domain_vt = await self.vt.lookup(report.domain)
            except SourceError as e:
                report.errors.append(f"(dominio) {e}")
