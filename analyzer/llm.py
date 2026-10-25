"""Análisis de los eventos con el modelo local (LM Studio).

El modelo recibe los eventos ya agrupados y devuelve, para cada uno, la
gravedad, una explicación corta y qué hacer. Si el modelo no responde, se usa
una clasificación por reglas para no perder la alerta.
"""
import json
import re

import requests

from .config import config

SYSTEM_PROMPT = """Eres un administrador de sistemas Linux con experiencia en seguridad.
Recibirás eventos detectados en los logs de un servidor Ubuntu con SSH, Nginx y MySQL.
Para cada evento devuelve:
- severidad: "baja", "media", "alta" o "critica"
- titulo: máximo 8 palabras
- explicacion: qué está pasando, en 1-2 frases sencillas
- recomendacion: qué debería hacer el administrador, en 1-2 frases concretas (comandos si ayudan)
Criterios: un acceso correcto después de muchos fallos es "critica"; fuerza bruta SSH es "alta"
si hay más de 20 intentos, si no "media"; servicio caído es "alta"; disco por encima del 95% es
"critica". No inventes datos que no estén en los eventos.
Responde SOLO con JSON con este formato: {"incidencias": [{"evento": <índice>, "severidad": "...",
"titulo": "...", "explicacion": "...", "recomendacion": "..."}]}"""

SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "analisis",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "incidencias": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "evento": {"type": "integer"},
                            "severidad": {"type": "string", "enum": ["baja", "media", "alta", "critica"]},
                            "titulo": {"type": "string"},
                            "explicacion": {"type": "string"},
                            "recomendacion": {"type": "string"},
                        },
                        "required": ["evento", "severidad", "titulo", "explicacion", "recomendacion"],
                    },
                }
            },
            "required": ["incidencias"],
        },
    },
}

SEVERITIES = ["baja", "media", "alta", "critica"]


def _extract_json(text):
    """Saca el primer objeto JSON del texto (por si el modelo añade algo más)."""
    text = re.sub(r"```(?:json)?", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("La respuesta del modelo no contiene JSON")
    return json.loads(text[start : end + 1])


def _ask_model(events):
    numbered = [{"indice": i, **e} for i, e in enumerate(events)]
    payload = {
        "model": config.llm_model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(numbered, ensure_ascii=False, indent=1)},
        ],
        "response_format": SCHEMA,
    }
    url = config.llm_url.rstrip("/") + "/chat/completions"
    r = requests.post(url, json=payload, timeout=config.llm_timeout)
    if r.status_code == 400:
        # Algunos modelos/versiones no aceptan response_format: reintentamos sin él
        payload.pop("response_format")
        r = requests.post(url, json=payload, timeout=config.llm_timeout)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    return _extract_json(content)["incidencias"]


def _rule_based(event):
    """Clasificación de respaldo si el modelo no está disponible."""
    t = event["type"]
    if t == "acceso_tras_fallos":
        sev = "critica"
    elif t == "fuerza_bruta_ssh":
        sev = "alta" if event["intentos"] > 20 else "media"
    elif t == "servicio_caido":
        sev = "alta"
    elif t == "disco_lleno":
        sev = "critica" if event["uso_porcentaje"] >= 95 else "alta"
    elif t in ("errores_5xx", "errores_nginx", "errores_mysql"):
        sev = "media"
    else:
        sev = "baja"
    return {
        "severidad": sev,
        "titulo": t.replace("_", " ").capitalize(),
        "explicacion": "Clasificado por reglas (el modelo de IA no respondió).",
        "recomendacion": "Revisar el evento manualmente.",
    }


def _severity_floor(event):
    t = event["type"]
    if t == "acceso_tras_fallos":
        return "critica"
    if t == "servicio_caido":
        return "alta"
    if t == "disco_lleno" and event["uso_porcentaje"] >= 95:
        return "critica"
    return None


def analyze(events):
    """Devuelve una lista de incidencias: evento + análisis."""
    if not events:
        return []
    by_index = {}
    analyzed_by = "ia"
    try:
        for item in _ask_model(events):
            idx = item.get("evento")
            if isinstance(idx, int) and 0 <= idx < len(events) and item.get("severidad") in SEVERITIES:
                by_index[idx] = item
    except (requests.RequestException, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"[aviso] No se pudo usar el modelo: {exc}")
        analyzed_by = "reglas"

    incidents = []
    for i, event in enumerate(events):
        analysis = by_index.get(i)
        source = analyzed_by
        if analysis is None:          # el modelo se saltó este evento
            analysis = _rule_based(event)
            source = "reglas"
        severity = analysis["severidad"]
        # Red de seguridad: la IA nunca puede bajar la gravedad mínima de ciertos casos
        floor = _severity_floor(event)
        if floor and SEVERITIES.index(severity) < SEVERITIES.index(floor):
            severity = floor
        incidents.append({
            "event": event,
            "severity": severity,
            "title": analysis["titulo"],
            "explanation": analysis["explicacion"],
            "recommendation": analysis["recomendacion"],
            "analyzed_by": source,
        })
    return incidents
