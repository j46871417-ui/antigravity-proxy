FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    haproxy \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY proxy.py /app/proxy.py
COPY haproxy.cfg /etc/haproxy/haproxy.cfg

RUN mkdir -p /etc/antigravity-proxy && \
    openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/antigravity-proxy/proxy.key \
    -out /etc/antigravity-proxy/proxy.crt \
    -days 3650 \
    -subj "/CN=antigravity.proxy/O=Antigravity/C=EU" && \
    cat /etc/antigravity-proxy/proxy.key /etc/antigravity-proxy/proxy.crt > /etc/antigravity-proxy/proxy_bundle.pem && \
    chmod 600 /etc/antigravity-proxy/proxy_bundle.pem

EXPOSE 50128

CMD haproxy -f /etc/haproxy/haproxy.cfg -D && python3 /app/proxy.py
