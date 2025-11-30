FROM python:3.12-slim
LABEL maintainer="support@duocircle.com"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install pip-tools for dependency management
RUN pip install --no-cache-dir pip-tools

# Copy requirements files
COPY requirements.in .

# Compile and install dependencies
RUN pip-compile requirements.in -o requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/

# Set Python path
ENV PYTHONPATH=/app/src

EXPOSE 8000/tcp

ENTRYPOINT ["python", "-m", "spf_guru"]
