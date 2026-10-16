FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/remote222
COPY remote222/ ./remote222/

RUN mkdir -p /var/data/remote222 && chmod 700 /var/data/remote222

EXPOSE 8770

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8770/healthz', timeout=3).close()"

CMD ["python", "-m", "remote222.broker", "--host", "0.0.0.0", "--port", "8770", "--state-dir", "/var/data/remote222"]
