# Usa una imagen oficial de Python como base
FROM python:3.11-slim

# Establece la zona horaria para que los logs sean consistentes
ENV TZ=America/Santiago
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Actualiza el gestor de paquetes e instala poppler-utils
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copia primero el archivo de requerimientos para aprovechar el caché de Docker
COPY requirements.txt .

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de tu aplicación al contenedor
COPY . .

# Expone el puerto en el que tu aplicación se ejecuta
EXPOSE 10000

# El comando para iniciar tu aplicación con las optimizaciones de memoria
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "--workers", "1", "--timeout", "120", "--preload", "app:app"]

