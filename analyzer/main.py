"""Punto de entrada.

Uso:
  python -m analyzer.main            # analiza los logs nuevos (lo lanza el timer cada 5 min)
  python -m analyzer.main --report   # envía el informe de las últimas 24 h
  python -m analyzer.main --dry-run  # analiza y muestra el resultado sin guardar ni avisar
"""
import argparse
import json

from . import collectors, llm, notifier
from .config import config

SEVERITIES = ["baja", "media", "alta", "critica"]
# Estos problemas siguen "activos" en cada ejecución: no los guardamos repetidos
PERSISTENT_TYPES = {"disco_lleno", "servicio_caido"}


def should_alert(severity):
    return SEVERITIES.index(severity) >= SEVERITIES.index(config.alert_min_severity)


def run(dry_run=False):
    events = collectors.collect_all()
    if not events:
        print("Sin eventos nuevos.")
        return
    print(f"{len(events)} eventos detectados, analizando con el modelo...")
    incidents = llm.analyze(events)

    if dry_run:
        for inc in incidents:
            print(json.dumps(inc, ensure_ascii=False, indent=2))
            print(notifier.format_alert(inc), "\n")
        return

    from . import storage  # solo hace falta MySQL fuera del modo de prueba

    conn = storage.connect()
    for inc in incidents:
        fp = storage.fingerprint(inc["event"])
        recent = storage.was_alerted_recently(conn, fp)
        if recent and inc["event"]["type"] in PERSISTENT_TYPES:
            continue
        notified = False
        if should_alert(inc["severity"]) and not recent:
            notified = notifier.send(notifier.format_alert(inc))
        storage.save(conn, inc, fp, notified)
        print(f"[{inc['severity']}] {inc['title']} (avisado: {notified})")
    conn.close()


def report():
    from . import storage

    conn = storage.connect()
    rows = storage.incidents_last_24h(conn)
    conn.close()
    notifier.send(notifier.format_report(rows))


def main():
    parser = argparse.ArgumentParser(description="Analizador de logs con IA local")
    parser.add_argument("--report", action="store_true", help="enviar informe diario")
    parser.add_argument("--dry-run", action="store_true", help="no guardar ni enviar alertas")
    args = parser.parse_args()
    if args.report:
        report()
    else:
        run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
