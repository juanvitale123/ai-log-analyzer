"""Lectura de logs y comprobaciones del sistema.

Cada colector devuelve una lista de "eventos": diccionarios con lo que ha
pasado, ya agrupado. Así al modelo no le llegan miles de líneas, solo un
resumen (y además no se mandan más datos de los necesarios).
"""
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict

from .config import config

# ---------------------------------------------------------------------------
# Lectura incremental: solo las líneas nuevas desde la última ejecución
# ---------------------------------------------------------------------------


def _load_state():
    try:
        with open(config.state_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state):
    with open(config.state_file, "w") as f:
        json.dump(state, f)


def read_new_lines(path, state):
    """Devuelve las líneas añadidas a `path` desde la última lectura."""
    if not os.path.exists(path):
        return []
    st = os.stat(path)
    prev = state.get(path, {})
    offset = prev.get("offset", 0)
    # Si el archivo ha rotado (logrotate) o es más pequeño, empezamos de cero
    if prev.get("inode") != st.st_ino or st.st_size < offset:
        offset = 0
    with open(path, errors="replace") as f:
        f.seek(offset)
        lines = f.readlines()
        state[path] = {"inode": st.st_ino, "offset": f.tell()}
    return [line.rstrip("\n") for line in lines]


# ---------------------------------------------------------------------------
# SSH (auth.log)
# ---------------------------------------------------------------------------

RE_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
RE_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")
RE_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
RE_SUDO_FAIL = re.compile(r"sudo: +(\S+) : .*incorrect password attempts")


def ssh_events(lines):
    # sshd escribe "Invalid user X" y además "Failed password for invalid user X":
    # contamos cada tipo por separado y nos quedamos con el mayor para no duplicar.
    failed = Counter()
    invalid = Counter()
    users = defaultdict(set)
    accepted = []
    sudo_fails = Counter()

    for line in lines:
        m = RE_FAILED.search(line)
        if m:
            user, ip = m.groups()
            failed[ip] += 1
            users[ip].add(user)
            continue
        m = RE_INVALID.search(line)
        if m:
            user, ip = m.groups()
            invalid[ip] += 1
            users[ip].add(user)
            continue
        m = RE_ACCEPTED.search(line)
        if m:
            accepted.append({"user": m.group(1), "ip": m.group(2)})
            continue
        m = RE_SUDO_FAIL.search(line)
        if m:
            sudo_fails[m.group(1)] += 1

    fails = {
        ip: {"count": max(failed[ip], invalid[ip]), "users": users[ip]}
        for ip in set(failed) | set(invalid)
    }

    events = []
    for ip, data in fails.items():
        if data["count"] >= config.ssh_fail_threshold:
            events.append({
                "source": "ssh",
                "type": "fuerza_bruta_ssh",
                "ip": ip,
                "intentos": data["count"],
                "usuarios_probados": sorted(data["users"])[:10],
            })
    # Un acceso correcto desde una IP que antes ha fallado mucho es sospechoso
    for acc in accepted:
        if acc["ip"] in fails and fails[acc["ip"]]["count"] >= config.ssh_fail_threshold:
            events.append({
                "source": "ssh",
                "type": "acceso_tras_fallos",
                "ip": acc["ip"],
                "usuario": acc["user"],
                "fallos_previos": fails[acc["ip"]]["count"],
            })
    for user, n in sudo_fails.items():
        events.append({"source": "sudo", "type": "sudo_fallido", "usuario": user, "veces": n})
    return events


# ---------------------------------------------------------------------------
# Nginx
# ---------------------------------------------------------------------------

# Formato "combined" por defecto de Nginx
RE_ACCESS = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3})')
SCAN_PATHS = ("/wp-login", "/wp-admin", "/.env", "/phpmyadmin", "/.git", "/admin", "/xmlrpc.php")


def nginx_events(access_lines, error_lines):
    status_5xx = Counter()
    not_found_by_ip = Counter()
    scans_by_ip = defaultdict(set)

    for line in access_lines:
        m = RE_ACCESS.match(line)
        if not m:
            continue
        ip, _method, path, status = m.groups()
        if status.startswith("5"):
            status_5xx[path] += 1
        elif status == "404":
            not_found_by_ip[ip] += 1
        if path.startswith(SCAN_PATHS):
            scans_by_ip[ip].add(path)

    events = []
    total_5xx = sum(status_5xx.values())
    if total_5xx >= config.http_5xx_threshold:
        events.append({
            "source": "nginx",
            "type": "errores_5xx",
            "total": total_5xx,
            "rutas": dict(status_5xx.most_common(5)),
        })
    for ip, paths in scans_by_ip.items():
        events.append({
            "source": "nginx",
            "type": "escaneo_web",
            "ip": ip,
            "rutas_probadas": sorted(paths),
            "respuestas_404": not_found_by_ip.get(ip, 0),
        })

    # Del error.log nos quedamos con los mensajes distintos (sin repetir)
    errors = Counter()
    for line in error_lines:
        if "[error]" in line or "[crit]" in line or "[emerg]" in line:
            msg = re.sub(r"^\S+ \S+ ", "", line)          # quita fecha y hora
            msg = re.sub(r", client: .*", "", msg)       # quita datos del cliente
            errors[msg[:200]] += 1
    if errors:
        events.append({
            "source": "nginx",
            "type": "errores_nginx",
            "mensajes": dict(errors.most_common(5)),
        })
    return events


# ---------------------------------------------------------------------------
# MySQL
# ---------------------------------------------------------------------------


def mysql_events(lines):
    errors = Counter()
    for line in lines:
        if "[ERROR]" in line or "Access denied" in line:
            msg = re.sub(r"^\S+ \d+ ", "", line)
            errors[msg[:200]] += 1
    if not errors:
        return []
    return [{"source": "mysql", "type": "errores_mysql", "mensajes": dict(errors.most_common(5))}]


# ---------------------------------------------------------------------------
# Sistema: disco y servicios
# ---------------------------------------------------------------------------


def disk_events():
    events = []
    for mount in ("/", "/var"):
        if not os.path.exists(mount):
            continue
        usage = shutil.disk_usage(mount)
        percent = round(usage.used / usage.total * 100)
        if percent >= config.disk_usage_threshold:
            events.append({
                "source": "sistema",
                "type": "disco_lleno",
                "punto_montaje": mount,
                "uso_porcentaje": percent,
                "libre_gb": round(usage.free / 1024**3, 1),
            })
    # / y /var suelen ser el mismo disco: no repetimos el aviso
    seen, unique = set(), []
    for e in events:
        key = (e["uso_porcentaje"], e["libre_gb"])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique


def service_events():
    events = []
    for svc in [s.strip() for s in config.services.split(",") if s.strip()]:
        try:
            out = subprocess.run(
                ["systemctl", "is-active", svc], capture_output=True, text=True, timeout=10
            ).stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if out != "active":
            events.append({"source": "sistema", "type": "servicio_caido", "servicio": svc, "estado": out})
    return events


# ---------------------------------------------------------------------------


def collect_all():
    """Ejecuta todos los colectores y guarda hasta dónde se ha leído."""
    state = _load_state()
    events = []
    events += ssh_events(read_new_lines(config.auth_log, state))
    events += nginx_events(
        read_new_lines(config.nginx_access_log, state),
        read_new_lines(config.nginx_error_log, state),
    )
    events += mysql_events(read_new_lines(config.mysql_error_log, state))
    events += disk_events()
    events += service_events()
    _save_state(state)
    return events
