"""Envío de alertas por Telegram."""
import html

import requests

from .config import config

ICONS = {"baja": "🔵", "media": "🟡", "alta": "🟠", "critica": "🔴"}


def send(text):
    if not config.telegram_token or not config.telegram_chat_id:
        print("[aviso] Telegram no configurado; mensaje no enviado:\n" + text)
        return False
    url = f"https://api.telegram.org/bot{config.telegram_token}/sendMessage"
    try:
        r = requests.post(
            url,
            data={"chat_id": config.telegram_chat_id, "text": text, "parse_mode": "HTML"},
            timeout=15,
        )
        r.raise_for_status()
        return True
    except requests.RequestException as exc:
        # No imprimimos la URL porque lleva el token
        print(f"[error] No se pudo enviar a Telegram: {type(exc).__name__}")
        return False


def format_alert(incident):
    e = incident["event"]
    lines = [
        f"{ICONS[incident['severity']]} <b>{html.escape(incident['title'])}</b>",
        f"Servidor: <code>{html.escape(config.hostname)}</code> · Gravedad: <b>{incident['severity']}</b>",
    ]
    if e.get("ip"):
        lines.append(f"IP: <code>{html.escape(e['ip'])}</code>")
    lines += [
        "",
        html.escape(incident["explanation"]),
        "",
        f"<b>Qué hacer:</b> {html.escape(incident['recommendation'])}",
    ]
    if incident["analyzed_by"] == "reglas":
        lines.append("<i>(clasificado por reglas, la IA no respondió)</i>")
    return "\n".join(lines)


def format_report(rows):
    if not rows:
        return f"✅ <b>Informe diario · {html.escape(config.hostname)}</b>\nSin incidencias en las últimas 24 h."
    counts = {s: 0 for s in ICONS}
    for r in rows:
        counts[r["severity"]] += 1
    summary = " · ".join(f"{ICONS[s]} {n}" for s, n in counts.items() if n)
    lines = [f"📋 <b>Informe diario · {html.escape(config.hostname)}</b>", f"{len(rows)} incidencias: {summary}", ""]
    for r in rows[-15:]:
        hora = r["created_at"].strftime("%H:%M")
        ip = f" ({r['ip']})" if r["ip"] else ""
        lines.append(f"{hora} {ICONS[r['severity']]} {html.escape(r['title'])}{html.escape(ip)}")
    if len(rows) > 15:
        lines.append(f"… y {len(rows) - 15} más")
    return "\n".join(lines)
