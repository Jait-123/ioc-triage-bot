"""Convierte un Report en un mensaje HTML para Telegram."""
from datetime import datetime
from html import escape

from ioc.parser import IOCType, defang
from ioc.service import Report
from ioc.verdict import Verdict

HASHES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}


def show_ioc(report: Report) -> str:
    """Los hashes se muestran tal cual; IPs, dominios y URLs neutralizados."""
    value = report.ioc.value if report.ioc.type in HASHES else defang(report.ioc.value)
    return f"<code>{escape(value)}</code> ({report.ioc.type.value})"


def format_report(r: Report) -> str:
    if r.skipped:
        return f"ℹ️ {show_ioc(r)}\n{escape(r.skipped)}"

    lines = []
    if r.assessment:
        lines += [f"<b>{r.assessment.verdict.label}</b>", f"IOC: {show_ioc(r)}"]
    else:
        lines += ["❌ <b>No se pudo analizar</b>", f"IOC: {show_ioc(r)}"]

    if r.vt and r.vt.found:
        total = r.vt.malicious + r.vt.suspicious + r.vt.harmless + r.vt.undetected
        lines.append(f"VirusTotal: {r.vt.malicious}/{total} motores maliciosos")
    if r.abuse:
        lines.append(f"AbuseIPDB: {r.abuse.score}/100 · {r.abuse.total_reports} reportes")
        extra = " · ".join(escape(x) for x in (r.abuse.country, r.abuse.isp, r.abuse.usage_type) if x)
        if extra:
            lines.append(f"<i>{extra}</i>")

    if r.assessment and r.assessment.reasons:
        lines += ["", "<b>Motivos</b>"] + [f"• {escape(x)}" for x in r.assessment.reasons]
    if r.assessment and r.assessment.notes:
        lines += ["", "<b>Notas</b>"] + [f"• {escape(x)}" for x in r.assessment.notes]
    if r.errors:
        lines += [""] + [f"⚠️ {escape(e)}" for e in r.errors]

    links = []
    if r.vt and r.vt.link:
        links.append(f'<a href="{escape(r.vt.link)}">VirusTotal</a>')
    if r.abuse:
        links.append(f'<a href="{escape(r.abuse.link)}">AbuseIPDB</a>')
    if links:
        lines += ["", "🔗 " + " | ".join(links)]
    if r.from_cache:
        lines.append("<i>(resultado desde caché)</i>")
    return "\n".join(lines)


def format_history(rows: list[tuple]) -> str:
    if not rows:
        return "Todavía no hay consultas en el historial."
    lines = ["<b>Últimas consultas</b>"]
    for ts, ioc, ioc_type, verdict in rows:
        when = datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")
        shown = ioc if ioc_type in {t.value for t in HASHES} else defang(ioc)
        icon = Verdict[verdict].label.split()[0]
        lines.append(f"{icon} {when} · <code>{escape(shown)}</code>")
    return "\n".join(lines)