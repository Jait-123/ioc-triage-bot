"""Prueba manual del análisis completo desde la consola.  Uso: python consulta.py <IOC>"""
import asyncio
import os
import sys

import httpx
from dotenv import load_dotenv

from ioc.cache import Cache
from ioc.service import Analyzer
from ioc.sources import AbuseIPDBClient, VirusTotalClient


async def main(raw: str) -> None:
    load_dotenv()
    cache = Cache("ioc_cache.db")
    async with httpx.AsyncClient() as http:
        analyzer = Analyzer(VirusTotalClient(os.environ["VT_API_KEY"], http),
                            AbuseIPDBClient(os.environ["ABUSEIPDB_API_KEY"], http),
                            cache)
        r = await analyzer.analyze(raw)
    cache.close()

    print(f"IOC: {r.ioc.value}   tipo: {r.ioc.type.value}" + ("   (desde caché)" if r.from_cache else ""))
    if r.skipped:
        print(r.skipped)
        return
    for e in r.errors:
        print("ERROR:", e)
    if r.assessment:
        print("\nVeredicto:", r.assessment.verdict.label)
        for reason in r.assessment.reasons:
            print("  -", reason)
        for note in r.assessment.notes:
            print("  *", note)
    if r.vt and r.vt.link:
        print("\nVirusTotal:", r.vt.link)
    if r.domain_vt and r.domain_vt.link:
        print("Dominio en VirusTotal:", r.domain_vt.link)
    if r.abuse:
        print("AbuseIPDB:", r.abuse.link)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python consulta.py <IOC>")
        sys.exit(1)
    try:
        asyncio.run(main(sys.argv[1]))
    except ValueError as e:
        print(e)
        sys.exit(1)
