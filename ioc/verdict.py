"""Reglas de veredicto: combinan VirusTotal y AbuseIPDB en una sola conclusión."""
from dataclasses import dataclass, field
from enum import Enum

from ioc.sources import AbuseResult, VTResult

# --- Umbrales (decisión de diseño documentada en el README, no un estándar) ---
VT_MALICIOUS_MIN = 3      # motores que lo marcan como malicioso
VT_SUSPICIOUS_MIN = 2
ABUSE_MALICIOUS_MIN = 51  # abuseConfidenceScore (0-100)
ABUSE_SUSPICIOUS_MIN = 25


class Verdict(Enum):
    # el número ordena por gravedad: el veredicto final es el más grave de las fuentes
    UNKNOWN = (0, "⚪ Desconocido")
    CLEAN = (1, "🟢 Sin detecciones relevantes")
    SUSPICIOUS = (2, "🟠 Sospechoso")
    MALICIOUS = (3, "🔴 Malicioso")

    @property
    def severity(self) -> int:
        return self.value[0]

    @property
    def label(self) -> str:
        return self.value[1]


@dataclass
class Assessment:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)  # por qué se llegó al veredicto
    notes: list[str] = field(default_factory=list)    # contexto para el analista


def _from_vt(vt: VTResult, a: Assessment) -> Verdict:
    if not vt.found:
        a.notes.append("VirusTotal no tiene información de este IOC.")
        return Verdict.UNKNOWN
    if vt.malicious >= VT_MALICIOUS_MIN:
        a.reasons.append(f"VirusTotal: {vt.malicious} motores lo marcan como malicioso.")
        return Verdict.MALICIOUS
    if vt.malicious >= VT_SUSPICIOUS_MIN:
        a.reasons.append(f"VirusTotal: {vt.malicious} motores lo marcan como malicioso.")
        return Verdict.SUSPICIOUS
    if vt.malicious == 1:
        a.notes.append("VirusTotal: 1 detección aislada, probable falso positivo.")
    return Verdict.CLEAN


def _from_abuse(ab: AbuseResult, a: Assessment) -> Verdict:
    if ab.is_whitelisted:
        a.notes.append(f"AbuseIPDB: IP en lista blanca ({ab.total_reports} reportes ignorados).")
        return Verdict.CLEAN
    if ab.score >= ABUSE_MALICIOUS_MIN:
        a.reasons.append(f"AbuseIPDB: puntuación de abuso {ab.score}/100 ({ab.total_reports} reportes).")
        return Verdict.MALICIOUS
    if ab.score >= ABUSE_SUSPICIOUS_MIN:
        a.reasons.append(f"AbuseIPDB: puntuación de abuso {ab.score}/100 ({ab.total_reports} reportes).")
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def evaluate(vt: VTResult | None, abuse: AbuseResult | None) -> Assessment:
    """Evalúa cada fuente disponible y se queda con el veredicto más grave."""
    a = Assessment(Verdict.UNKNOWN)
    found = []
    if vt is not None:
        found.append(_from_vt(vt, a))
    if abuse is not None:
        found.append(_from_abuse(abuse, a))
    if found:
        a.verdict = max(found, key=lambda v: v.severity)
    if a.verdict is Verdict.CLEAN:
        a.notes.append("Sin detecciones no garantiza que sea seguro.")
    return a