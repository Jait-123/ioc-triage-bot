import os
from dotenv import load_dotenv

load_dotenv()
for var in ["TELEGRAM_TOKEN", "VT_API_KEY", "ABUSEIPDB_API_KEY", "ALLOWED_CHAT_IDS"]:
    valor = os.getenv(var)
    estado = "OK" if valor else "FALTA"
    print(f"{var}: {estado} ({len(valor) if valor else 0} caracteres)")