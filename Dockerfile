FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/CSOAI-ORG/iso-27001-ai-mcp"
LABEL org.opencontainers.image.vendor="MEOK AI Labs"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
COPY server.py .

RUN uv pip install --system --no-cache mcp>=1.0.0

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import server; print('OK')" || exit 1

CMD ["python", "server.py"]
