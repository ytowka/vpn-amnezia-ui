FROM docker:29-cli AS docker-cli
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY server.py awg_core.py monitoring.py guest_access.py container_init.py ./
COPY static ./static
COPY tests ./tests
RUN python3 -m unittest discover -s tests -v
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    STATE_DIR=/data/state CLIENT_DIR=/data/clients CLIENT_TEMPLATE=/data/template.conf PORT=8443
EXPOSE 8443
ENTRYPOINT ["python3", "/app/container_init.py"]
