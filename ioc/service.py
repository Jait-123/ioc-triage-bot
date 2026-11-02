"""Orquesta el análisis completo: parser -> caché -> fuentes -> veredicto -> historial."""
from dataclasses import dataclass, field

from ioc.cache import Cache
from ioc.parser import IOCType, ParsedIOC, is_public_ip, parse_ioc
from ioc.sources import (AbuseIPDBClient, AbuseResult, SourceError, VirusTotalClient,
                         VTResult)
from ioc.verdict import Assessment, evaluate


@dataclass
class Report:
    ioc: ParsedIOC
    assessment: Assessment | None = None
    vt: VTResult | None = None
    abuse: AbuseResult | None = None
    errors: list[str] = field(default_factory=list)
    from_cache: bool = False
    skipped: str | None = None   # motivo por el que no se consultó


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

        cached = self.cache.get(ioc.value)
        if cached:
            report.vt, report.abuse = cached
            report.from_cache = True
        else:
            try:
                report.vt = await self.vt.lookup(ioc)
            except SourceError as e:
                report.errors.append(str(e))
            if ioc.type is IOCType.IP:
                try:
                    report.abuse = await self.abuse.lookup(ioc.value)
                except SourceError as e:
                    report.errors.append(str(e))
            # Solo se guardan resultados completos: un error no debe quedar en caché 24 h
            if not report.errors:
                self.cache.set(ioc.value, report.vt, report.abuse)

        if report.vt or report.abuse:
            report.assessment = evaluate(report.vt, report.abuse)
            self.cache.log(ioc.value, ioc.type.value, report.assessment.verdict.name, chat_id)
        return report