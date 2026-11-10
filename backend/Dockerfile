# syntax=docker/dockerfile:1.7
# ── ThreatLens API ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ENVIRONMENT=production \
    LOG_FORMAT=json \
    PORT=8000

WORKDIR /app

RUN groupadd --system --gid 10001 threatlens \
 && useradd --system --uid 10001 --gid threatlens --home /app --shell /usr/sbin/nologin threatlens

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=threatlens:threatlens . .
RUN mkdir -p /app/data && chown -R threatlens:threatlens /app/data

USER threatlens
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/ready', timeout=4)" || exit 1

# A single worker keeps the in-process scheduler unique; sync endpoints run in a thread pool.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 30"]
