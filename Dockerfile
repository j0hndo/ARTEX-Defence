FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY canary/ /app/canary/

RUN groupadd --gid 10001 canary \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin canary \
    && install -d -o canary -g canary /var/log/canary

USER 10001:10001

CMD ["python", "-m", "canary.server"]
