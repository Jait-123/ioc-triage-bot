import pytest

from ioc.parser import IOCType, is_public_ip, parse_ioc, refang


@pytest.mark.parametrize("raw, expected", [
    ("hxxp://malo[.]com/x", "http://malo.com/x"),
    ("HXXPS://malo[.]com", "https://malo.com"),
    ("8[.]8[.]8[.]8", "8.8.8.8"),
    ("  ejemplo(.)com  ", "ejemplo.com"),
])
def test_refang(raw, expected):
    assert refang(raw) == expected


@pytest.mark.parametrize("raw, expected_type", [
    ("8.8.8.8", IOCType.IP),
    ("2001:4860:4860::8888", IOCType.IP),
    ("google.com", IOCType.DOMAIN),
    ("sub.dominio.co.pe", IOCType.DOMAIN),
    ("hxxps://malo[.]com/login", IOCType.URL),
    ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
    ("3395856ce81f2b7382dee72602f798b642f14140", IOCType.SHA1),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IOCType.SHA256),
])
def test_detecta_tipo(raw, expected_type):
    assert parse_ioc(raw).type == expected_type


@pytest.mark.parametrize("raw", [
    "hola",
    "999.1.1.1",
    "abc123",          # hex corto: no es hash
    "http://",         # URL sin host
    "dominio.123",     # TLD numérico
    "",
])
def test_rechaza_invalidos(raw):
    with pytest.raises(ValueError):
        parse_ioc(raw)


def test_normaliza_minusculas():
    assert parse_ioc("GOOGLE.COM").value == "google.com"


@pytest.mark.parametrize("ip, esperado", [
    ("8.8.8.8", True),
    ("192.168.1.10", False),
    ("10.0.2.15", False),
    ("127.0.0.1", False),
])
def test_ip_publica(ip, esperado):
    assert is_public_ip(ip) is esperado