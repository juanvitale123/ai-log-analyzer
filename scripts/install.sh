#!/usr/bin/env bash
# Instala el analizador en /opt/ai-log-analyzer y activa los timers.
# Uso:  sudo ./scripts/install.sh
set -euo pipefail

DEST=/opt/ai-log-analyzer
SRC="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta con sudo." >&2
  exit 1
fi

# Usuario sin login, dentro del grupo adm para poder leer /var/log
id loganalyzer &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin loganalyzer
usermod -aG adm loganalyzer

mkdir -p "$DEST"
cp -r "$SRC/analyzer" "$SRC/requirements.txt" "$DEST/"
[[ -f "$DEST/.env" ]] || cp "$SRC/.env.example" "$DEST/.env"

python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

chown -R loganalyzer:adm "$DEST"
chmod 600 "$DEST/.env"      # el .env lleva contraseñas y el token

cp "$SRC"/deploy/*.service "$SRC"/deploy/*.timer /etc/systemd/system/
systemctl daemon-reload

echo
echo "Instalado en $DEST."
echo "1) Edita la configuración:   sudo nano $DEST/.env"
echo "2) Crea la base de datos:    sudo mysql < $SRC/sql/schema.sql"
echo "3) Prueba manual:            sudo systemctl start ai-log-analyzer && journalctl -u ai-log-analyzer -n 30"
echo "4) Activa los timers:        sudo systemctl enable --now ai-log-analyzer.timer ai-log-report.timer"
