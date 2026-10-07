#!/usr/bin/env bash
# Запуск: ./run.sh  (читає змінні з .env)
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a
exec python3 server.py
