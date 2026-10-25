"""Configuración leída del archivo .env."""
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _int(name, default):
    return int(os.getenv(name, default))


@dataclass
class Config:
    # Logs a vigilar
    auth_log: str = os.getenv("AUTH_LOG", "/var/log/auth.log")
    nginx_access_log: str = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
    nginx_error_log: str = os.getenv("NGINX_ERROR_LOG", "/var/log/nginx/error.log")
    mysql_error_log: str = os.getenv("MYSQL_ERROR_LOG", "/var/log/mysql/error.log")
    state_file: str = os.getenv("STATE_FILE", str(BASE_DIR / "state.json"))

    # Umbrales
    ssh_fail_threshold: int = _int("SSH_FAIL_THRESHOLD", 5)
    http_5xx_threshold: int = _int("HTTP_5XX_THRESHOLD", 10)
    disk_usage_threshold: int = _int("DISK_USAGE_THRESHOLD", 85)
    services: str = os.getenv("SERVICES", "ssh,nginx,mysql")

    # LLM local (LM Studio, API compatible con OpenAI)
    llm_url: str = os.getenv("LLM_URL", "http://localhost:1234/v1")
    llm_model: str = os.getenv("LLM_MODEL", "google/gemma-4-26b-a4b-qat")
    llm_timeout: int = _int("LLM_TIMEOUT", 120)

    # Base de datos (MySQL)
    db_host: str = os.getenv("DB_HOST", "localhost")
    db_user: str = os.getenv("DB_USER", "loganalyzer")
    db_password: str = os.getenv("DB_PASSWORD", "")
    db_name: str = os.getenv("DB_NAME", "loganalyzer")

    # Telegram
    telegram_token: str = os.getenv("TELEGRAM_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    # Solo se avisa por Telegram a partir de esta gravedad
    alert_min_severity: str = os.getenv("ALERT_MIN_SEVERITY", "media")

    hostname: str = os.getenv("SERVER_NAME", os.uname().nodename)


config = Config()
