# Dockerfile para LexGuard
FROM python:3.11-slim

# Variables de entorno para evitar bytecode y buffering
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY pyproject.toml .
COPY README.md .

# Instalar pip y dependencias del proyecto
RUN pip install --upgrade pip \
    && pip install .

# Copiar el código fuente
COPY lexguard/ ./lexguard/

# Copiar el entrypoint CLI
COPY lexguard/interfaces/cli/main.py ./lexguard/interfaces/cli/main.py

# Comando por defecto (CLI help)
ENTRYPOINT ["python", "-m", "lexguard.interfaces.cli.main"]
CMD ["--help"]
