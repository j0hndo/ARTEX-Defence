FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY canary/ /app/canary/

RUN mkdir -p /var/log/canary

CMD ["python", "-m", "canary.server"]
