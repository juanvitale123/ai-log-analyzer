#!/usr/bin/env bash
# Simula un ataque de fuerza bruta SSH y un escaneo web contra TU PROPIA VM de pruebas.
# Mejor desde otro equipo (WSL en Windows u otra VM) para que se vea una IP distinta.
# Necesita sshpass:  sudo apt install -y sshpass
# Uso:  ./scripts/simulate_attack.sh 192.168.1.50
set -u
TARGET="${1:?Indica la IP de la VM}"
command -v sshpass >/dev/null || { echo "Instala sshpass: sudo apt install -y sshpass"; exit 1; }

echo "== Intentos SSH con usuarios y contraseñas incorrectos =="
for user in admin root test oracle postgres ubuntu guest; do
  for pass in 123456 password admin; do
    sshpass -p "$pass" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no \
        "$user@$TARGET" exit 2>/dev/null
  done
done

echo "== Escaneo web de rutas típicas =="
for path in /wp-login.php /wp-admin/ /.env /phpmyadmin/ /.git/config /admin /xmlrpc.php; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "http://$TARGET$path"
done
echo "Hecho. En menos de 2 minutos debería llegar la alerta (o lanza el analizador a mano)."
