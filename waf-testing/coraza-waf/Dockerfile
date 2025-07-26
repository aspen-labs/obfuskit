FROM golang:1.24 AS builder

WORKDIR /app

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2 --output caddy

EXPOSE 8081

FROM debian:bullseye-slim

WORKDIR /app

RUN mkdir -p /app/bin /app/logs

COPY --from=builder /app/caddy /app/bin/caddy
RUN chmod +x /app/bin/caddy
COPY Caddyfile /app/Caddyfile
COPY 403.html /app/403.html

CMD /app/bin/caddy run --config /app/Caddyfile --adapter caddyfile 2>&1 | tee /app/logs/caddy.log



