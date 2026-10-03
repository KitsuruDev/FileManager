#!/bin/sh
set -e

apk add --no-cache openssl >/dev/null

if [ ! -f /certs/server.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /certs/server.key \
        -out /certs/server.crt \
        -subj "/CN=nginx" \
        -addext "subjectAltName=DNS:nginx,DNS:localhost,IP:127.0.0.1"
    chmod 600 /certs/server.key
    echo "[+] Сертификаты созданы"
else
    echo "[i] Сертификаты уже существуют, пропуск."
fi