#!/usr/bin/env bash
# exit on error
set -o errexit

echo "--- Instalando dependencias del sistema ---"
apt-get update
apt-get install -y --no-install-recommends poppler-utils

echo "--- Instalando dependencias de Python ---"
pip install -r requirements.txt

echo "--- Compilación finalizada exitosamente ---"