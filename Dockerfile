FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PII_VAULT_DIR=/data/vaults \
    PII_INPUT_DIR=/data/input \
    PII_OUTPUT_DIR=/data/output

WORKDIR /app

RUN useradd --create-home --shell /bin/bash vault \
    && mkdir -p /data/vaults /data/input /data/output \
    && chown -R vault:vault /data

COPY pyproject.toml README.md ./
COPY pii_vault ./pii_vault

RUN pip install --no-cache-dir -e ".[mcp]" && chown -R vault:vault /app

USER vault

ENTRYPOINT ["pii-vault"]
CMD ["mcp"]
