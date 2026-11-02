"""Limpieza (refang) y detección del tipo de IOC."""
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "dominio"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


@dataclass
class ParsedIOC:
    value: str
    type: IOCType


# Longitud del hash en caracteres hexadecimales -> tipo
HASH_LENGTHS = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
# Etiquetas de 1-63 caracteres separadas por puntos y TLD de solo letras (2+)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def refang(text: str) -> str:
    """Convierte un IOC 'neutralizado' a su forma real."""
    text = text.strip()
    # hxxp / hxxps (en mayúsculas o minúsculas) -> http / https
    text = re.sub(r"^hxxp(s?)", lambda m: "http" + m.group(1).lower(), text, flags=re.IGNORECASE)
    for fake, real in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":")):
        text = text.replace(fake, real)
    return text


def detect_type(value: str) -> IOCType | None:
    """Devuelve el tipo de IOC o None si no se reconoce."""
    # 1. URL: tiene esquema http/https y un host
    if value.lower().startswith(("http://", "https://")):
        return IOCType.URL if urlparse(value).netloc else None

    # 2. IP (v4 o v6): la valida el módulo estándar ipaddress
    try:
        ipaddress.ip_address(value)
        return IOCType.IP
    except ValueError:
        pass

    # 3. Hash: solo hexadecimal y longitud exacta
    if HEX_RE.match(value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)]

    # 4. Dominio
    if DOMAIN_RE.match(value.lower()):
        return IOCType.DOMAIN

    return None


def parse_ioc(raw: str) -> ParsedIOC:
    """Limpia, detecta y normaliza. Lanza ValueError si no es un IOC válido."""
    value = refang(raw)
    ioc_type = detect_type(value)
    if ioc_type is None:
        raise ValueError(f"No reconozco el IOC: {raw!r}")
    # Normalizar: dominios y hashes no distinguen mayúsculas
    if ioc_type is not IOCType.URL:
        value = value.lower()
    return ParsedIOC(value, ioc_type)


def is_public_ip(value: str) -> bool:
    """False para IPs privadas, loopback, reservadas, etc. (no tiene sentido consultarlas)."""
    return ipaddress.ip_address(value).is_global