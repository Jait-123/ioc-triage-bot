from ioc.cache import Cache
from ioc.sources import AbuseResult, VTResult

VT = VTResult(found=True, malicious=5, link="x")
AB = AbuseResult(score=80, total_reports=3, country="CN", isp="i",
                 usage_type="u", is_whitelisted=False, link="y")


def test_guarda_y_recupera(tmp_path):
    c = Cache(tmp_path / "t.db")
    c.set("1.2.3.4", VT, AB)
    assert c.get("1.2.3.4") == (VT, AB, None)


def test_expira_tras_ttl(tmp_path):
    t = [0.0]
    c = Cache(tmp_path / "t.db", ttl_hours=1, clock=lambda: t[0])
    c.set("google.com", VT, None)
    t[0] = 3601                      # pasa 1 hora y 1 segundo
    assert c.get("google.com") is None


def test_no_existe(tmp_path):
    assert Cache(tmp_path / "t.db").get("nada.com") is None


def test_historial_mas_reciente_primero(tmp_path):
    c = Cache(tmp_path / "t.db")
    c.log("a.com", "dominio", "CLEAN")
    c.log("b.com", "dominio", "MALICIOUS")
    assert [h[1] for h in c.history()] == ["b.com", "a.com"]


def test_inyeccion_sql_se_trata_como_texto(tmp_path):
    c = Cache(tmp_path / "t.db")
    c.log("x'); DROP TABLE history;--", "dominio", "CLEAN")
    assert len(c.history()) == 1     # la tabla sigue existiendo


def test_ttl_propio_por_resultado(tmp_path):
    t = [0.0]
    c = Cache(tmp_path / "t.db", ttl_hours=24, clock=lambda: t[0])
    c.set("http://x.com/a", VTResult(found=False), None, ttl_hours=1)
    c.set("google.com", VT, None)
    t[0] = 3601                      # 1 h y 1 s después
    assert c.get("http://x.com/a") is None        # el desconocido ya caducó
    assert c.get("google.com") is not None        # el resto sigue vigente
