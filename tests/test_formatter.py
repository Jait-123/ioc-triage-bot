from ioc.formatter import format_history, format_report
from ioc.parser import defang, parse_ioc
from ioc.service import Report
from ioc.sources import AbuseResult, VTResult
from ioc.verdict import evaluate


def test_defang():
    assert defang("http://malo.com/x") == "hxxp://malo[.]com/x"
    assert defang("1.2.3.4") == "1[.]2[.]3[.]4"


def test_url_se_muestra_neutralizada():
    r = Report(parse_ioc("http://malo.com/login"), vt=VTResult(found=True, malicious=5, link="https://vt/x"))
    r.assessment = evaluate(r.vt, None)
    msg = format_report(r)
    assert "hxxp://malo[.]com/login" in msg
    assert "http://malo.com" not in msg


def test_hash_no_se_modifica():
    h = "44d88612fea8a8f36de82e1278abb02f"
    r = Report(parse_ioc(h), vt=VTResult(found=True, malicious=66, undetected=3))
    r.assessment = evaluate(r.vt, None)
    assert h in format_report(r)


def test_escapa_html_del_proveedor():
    ab = AbuseResult(80, 5, "CN", "<script>ISP</script>", "x", False, "https://a/1")
    r = Report(parse_ioc("1.2.3.4"), abuse=ab)
    r.assessment = evaluate(None, ab)
    assert "<script>" not in format_report(r)


def test_ip_privada():
    r = Report(parse_ioc("10.0.0.1"), skipped="IP privada")
    assert "IP privada" in format_report(r)


def test_sin_veredicto_muestra_errores():
    r = Report(parse_ioc("google.com"), errors=["VirusTotal: límite alcanzado"])
    msg = format_report(r)
    assert "No se pudo analizar" in msg and "límite" in msg


def test_historial():
    msg = format_history([(0, "malo.com", "dominio", "MALICIOUS")])
    assert "malo[.]com" in msg and "🔴" in msg
    assert "Todavía" in format_history([])


def test_url_desconocida_muestra_dominio_neutralizado():
    from ioc.service import url_host
    url = "https://best.aliexpress.com/?x=1"
    r = Report(parse_ioc(url), vt=VTResult(found=False),
               domain=url_host(url), domain_vt=VTResult(found=True, harmless=60, link="https://vt/d"))
    r.assessment = evaluate(r.vt, None, r.domain_vt)
    msg = format_report(r)
    assert "best[.]aliexpress[.]com" in msg and "no analizada" in msg
