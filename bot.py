"""Bot de Telegram para triage de IOCs.  Ejecutar: python bot.py"""
import logging
import os

import httpx
from dotenv import load_dotenv
from telegram import LinkPreviewOptions, Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (Application, CommandHandler, ContextTypes, Defaults,
                          MessageHandler, filters)

from ioc.cache import Cache
from ioc.formatter import format_history, format_report
from ioc.service import Analyzer
from ioc.sources import AbuseIPDBClient, VirusTotalClient

load_dotenv()
logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
# httpx registra cada URL en INFO, y la URL de Telegram CONTIENE el token: lo silenciamos
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("ioc-bot")

ALLOWED_IDS = {int(x) for x in os.environ["ALLOWED_CHAT_IDS"].split(",") if x.strip()}
AUTH = filters.Chat(chat_id=ALLOWED_IDS)

AYUDA = (
    "<b>Bot de triage de IOCs</b>\n"
    "Envíame un indicador y lo analizo con VirusTotal y AbuseIPDB:\n"
    "• IP: <code>1.2.3.4</code>\n"
    "• Dominio: <code>ejemplo[.]com</code>\n"
    "• URL: <code>hxxps://ejemplo[.]com/login</code>\n"
    "• Hash: MD5, SHA1 o SHA256\n\n"
    "Acepto IOCs neutralizados (hxxp, [.]).\n"
    "/historial — últimas consultas"
)


async def post_init(app: Application) -> None:
    """Se ejecuta una vez al arrancar: crea los recursos compartidos."""
    http = httpx.AsyncClient()
    cache = Cache("ioc_cache.db")
    app.bot_data["http"] = http
    app.bot_data["cache"] = cache
    app.bot_data["analyzer"] = Analyzer(
        VirusTotalClient(os.environ["VT_API_KEY"], http),
        AbuseIPDBClient(os.environ["ABUSEIPDB_API_KEY"], http),
        cache,
    )
    log.info("Bot iniciado. Chats autorizados: %d", len(ALLOWED_IDS))


async def post_shutdown(app: Application) -> None:
    await app.bot_data["http"].aclose()
    app.bot_data["cache"].close()


async def ayuda(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(AYUDA)


async def historial(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    rows = context.bot_data["cache"].history(limit=10)
    await update.message.reply_text(format_history(rows))


async def analizar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        report = await context.bot_data["analyzer"].analyze(
            update.message.text, chat_id=update.effective_chat.id)
    except ValueError:
        await update.message.reply_text("No reconozco eso como IOC. Usa /ayuda para ver ejemplos.")
        return
    log.info("Consulta %s (%s) -> %s", report.ioc.type.value,
             "caché" if report.from_cache else "API",
             report.assessment.verdict.name if report.assessment else "sin veredicto")
    await update.message.reply_text(format_report(report))


async def no_autorizado(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """No respondemos (no confirmamos que el bot existe), pero queda registro."""
    user = update.effective_user
    log.warning("Acceso no autorizado: chat_id=%s usuario=%s",
                update.effective_chat.id if update.effective_chat else "?",
                user.username if user else "?")


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Error no controlado", exc_info=context.error)


def main() -> None:
    defaults = Defaults(
        parse_mode=ParseMode.HTML,
        # Sin vista previa: Telegram NO visitará los enlaces que aparezcan en las respuestas
        link_preview_options=LinkPreviewOptions(is_disabled=True),
    )
    app = (Application.builder()
           .token(os.environ["TELEGRAM_TOKEN"])
           .defaults(defaults)
           .post_init(post_init)
           .post_shutdown(post_shutdown)
           .build())

    app.add_handler(CommandHandler(["start", "ayuda"], ayuda, filters=AUTH))
    app.add_handler(CommandHandler("historial", historial, filters=AUTH))
    app.add_handler(MessageHandler(AUTH & filters.TEXT & ~filters.COMMAND, analizar))
    app.add_handler(MessageHandler(~AUTH, no_autorizado))
    app.add_error_handler(on_error)

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()