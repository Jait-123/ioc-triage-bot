"""Prueba manual de las fuentes desde la consola.  Uso: python consulta.py <IOC>"""
import asyncio
import os
import sys

import httpx
from dotenv import load_dotenv

from ioc.parser import IOCType, is_public_ip, parse_ioc
from ioc.sources import AbuseIPDBClient, SourceError, VirusTotalClient


async def main(raw: str) -> None:
    load_dotenv()
    ioc = parse_ioc(raw)
    print(f"IOC: {ioc.value}   tipo: {ioc.type.value}\n")

    if ioc.type is IOCType.IP and not is_public_ip(ioc.value):
        print("IP privada o reservada: no tiene reputación pública, no se consulta.")
        return

    async with httpx.AsyncClient() as http:
        vt = VirusTotalClient(os.environ["VT_API_KEY"], http)
        try:
            print("VirusTotal:", await vt.lookup(ioc))
        except SourceError as e:
            print("VirusTotal ERROR:", e)

        if ioc.type is IOCType.IP:
            abuse = AbuseIPDBClient(os.environ["ABUSEIPDB_API_KEY"], http)
            try:
                print("AbuseIPDB:", await abuse.lookup(ioc.value))
            except SourceError as e:
                print("AbuseIPDB ERROR:", e)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python consulta.py <IOC>")
        sys.exit(1)
    try:
        asyncio.run(main(sys.argv[1]))
    except ValueError as e:
        print(e)
        sys.exit(1)