# Usa una imagen oficial de Python como base
FROM python:3.11-slim

# Establece la zona horaria para que los logs sean consistentes
ENV TZ=America/Santiago
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Actualiza el gestor de paquetes e instala poppler-utils y otras herramientas
# Esto se ejecuta como root DENTRO del proceso de construcción de la imagen, por lo que funcionará.
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copia primero el archivo de requerimientos para aprovechar el caché de Docker
COPY requirements.txt .

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de tu aplicación al contenedor
COPY . .

# Expone el puerto en el que tu aplicación se ejecuta (los logs de Render mencionan el 10000)
EXPOSE 10000

# El comando para iniciar tu aplicación cuando el contenedor arranque
# Usa Gunicorn para producción, es más robusto que el servidor de desarrollo de Flask
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "--workers", "4", "app:app"]