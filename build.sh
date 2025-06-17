#!/usr/bin/env bash
# exit on error
set -o errexit

# 1. Instala las dependencias del sistema operativo (Poppler)
apt-get update && apt-get install -y poppler-utils

# 2. Instala las dependencias de Python
pip install -r requirements.txt