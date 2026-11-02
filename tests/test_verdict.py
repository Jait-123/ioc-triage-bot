"""Casos basados en resultados REALES observados en la Fase 2."""
from ioc.sources import AbuseResult, VTResult
from ioc.verdict import Verdict, evaluate


def vt(malicious, found=True):
    return VTResult(found=found, malicious=malicious, harmless=50, undetected=30)


def abuse(score, whitelisted=False, reports=10):
    return AbuseResult(score=score, total_reports=reports, country="US", isp="x",
                       usage_type="x", is_whitelisted=whitelisted, link="x")


def test_eicar_es_malicioso():                       # real: 60 motores
    assert evaluate(vt(60), None).verdict is Verdict.MALICIOUS


def test_google_una_deteccion_no_es_sospechoso():    # real: google.com 1 motor
    a = evaluate(vt(1), None)
    assert a.verdict is Verdict.CLEAN
    assert any("aislada" in n for n in a.notes)


def test_8888_lista_blanca_ignora_reportes():        # real: 8.8.8.8, 200 reportes, score 0
    a = evaluate(vt(1), abuse(0, whitelisted=True, reports=200))
    assert a.verdict is Verdict.CLEAN


def test_dos_motores_es_sospechoso():
    assert evaluate(vt(2), None).verdict is Verdict.SUSPICIOUS


def test_umbrales_abuseipdb():
    assert evaluate(None, abuse(24)).verdict is Verdict.CLEAN
    assert evaluate(None, abuse(25)).verdict is Verdict.SUSPICIOUS
    assert evaluate(None, abuse(50)).verdict is Verdict.SUSPICIOUS
    assert evaluate(None, abuse(51)).verdict is Verdict.MALICIOUS


def test_gana_la_fuente_mas_grave():
    assert evaluate(vt(0), abuse(90)).verdict is Verdict.MALICIOUS


def test_vt_desconoce_y_sin_mas_datos():
    assert evaluate(vt(0, found=False), None).verdict is Verdict.UNKNOWN


def test_vt_desconoce_pero_abuseipdb_alto():
    assert evaluate(vt(0, found=False), abuse(80)).verdict is Verdict.MALICIOUS


def test_limpio_avisa_que_no_garantiza_seguridad():
    a = evaluate(vt(0), None)
    assert any("no garantiza" in n for n in a.notes)


# ---------- URL desconocida + contexto del dominio ----------

def test_url_desconocida_dominio_limpio_sigue_desconocida():   # real: enlace de AliExpress
    a = evaluate(vt(0, found=False), None, domain_vt=vt(0))
    assert a.verdict is Verdict.UNKNOWN
    assert any("URL exacta" in n for n in a.notes)


def test_url_desconocida_dominio_malicioso_sube_veredicto():
    assert evaluate(vt(0, found=False), None, domain_vt=vt(8)).verdict is Verdict.MALICIOUS


def test_url_desconocida_dominio_sospechoso():
    assert evaluate(vt(0, found=False), None, domain_vt=vt(2)).verdict is Verdict.SUSPICIOUS


def test_dominio_con_una_deteccion_no_sube_veredicto():
    assert evaluate(vt(0, found=False), None, domain_vt=vt(1)).verdict is Verdict.UNKNOWN
