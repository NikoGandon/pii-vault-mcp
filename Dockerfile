FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SYMBOLON_VAULT_DIR=/data/vaults \
    SYMBOLON_INPUT_DIR=/data/input \
    SYMBOLON_OUTPUT_DIR=/data/output

WORKDIR /app

RUN useradd --create-home --shell /bin/bash vault \
    && mkdir -p /data/vaults /data/input /data/output \
    && chown -R vault:vault /data

COPY pyproject.toml README.md ./
COPY symbolon ./symbolon

RUN pip install --no-cache-dir -e ".[mcp]" && chown -R vault:vault /app

USER vault

ENTRYPOINT ["symbolon"]
CMD ["mcp"]
