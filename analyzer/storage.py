"""Guardado de incidencias en MySQL."""
import hashlib
import json

import pymysql

from .config import config


def connect():
    return pymysql.connect(
        host=config.db_host,
        user=config.db_user,
        password=config.db_password,
        database=config.db_name,
        charset="utf8mb4",
        autocommit=True,
    )


def fingerprint(event):
    """Identifica un problema "igual" para no repetir la misma alerta.

    Para fuerza bruta usamos tipo + IP; para disco o servicios, tipo + recurso.
    """
    key_fields = {k: event[k] for k in ("type", "ip", "servicio", "punto_montaje") if k in event}
    raw = json.dumps(key_fields, sort_keys=True)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def was_alerted_recently(conn, fp, minutes=60):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM incidents WHERE fingerprint=%s AND notified=1 "
            "AND created_at > NOW() - INTERVAL %s MINUTE LIMIT 1",
            (fp, minutes),
        )
        return cur.fetchone() is not None


def save(conn, incident, fp, notified):
    e = incident["event"]
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO incidents
               (server, source, type, severity, title, explanation, recommendation,
                ip, details, analyzed_by, fingerprint, notified)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                config.hostname,
                e["source"],
                e["type"],
                incident["severity"],
                incident["title"][:150],
                incident["explanation"],
                incident["recommendation"],
                e.get("ip"),
                json.dumps(e, ensure_ascii=False),
                incident["analyzed_by"],
                fp,
                int(notified),
            ),
        )


def incidents_last_24h(conn):
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(
            "SELECT severity, type, title, ip, created_at FROM incidents "
            "WHERE created_at > NOW() - INTERVAL 1 DAY ORDER BY created_at"
        )
        return cur.fetchall()
