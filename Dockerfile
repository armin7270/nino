# ==============================================================================
# Nino Dashboard — container image
# ==============================================================================

FROM debian:bookworm-slim AS core-bin

ARG TARGETARCH=amd64
ARG ANYTLS_VERSION=v0.0.13

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH}"; \
    case "$arch" in \
      amd64|arm64) ;; \
      *) echo "Unsupported TARGETARCH: $arch" >&2; exit 1 ;; \
    esac; \
    ver="${ANYTLS_VERSION#v}"; \
    url="https://github.com/anytls/anytls-go/releases/download/${ANYTLS_VERSION}/anytls_${ver}_linux_${arch}.zip"; \
    echo "Downloading ${url}"; \
    curl -fsSL --retry 3 --retry-delay 2 -o /tmp/anytls.zip "$url"; \
    mkdir -p /out; \
    unzip -o /tmp/anytls.zip -d /tmp/anytls; \
    find /tmp/anytls -type f -name 'anytls-server' -exec install -m 0755 {} /out/anytls-server \; ; \
    test -x /out/anytls-server; \
    /out/anytls-server --help >/dev/null 2>&1 || true


# ------------------------------------------------------------------------------
# 2. Build the panel (SPA + bundled Express server)
# ------------------------------------------------------------------------------
FROM node:22-bookworm-slim AS build

WORKDIR /app

# Install dependencies first so Docker layer caching survives source edits.
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build


# ------------------------------------------------------------------------------
# 3. Runtime
# ------------------------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime

# ca-certificates + curl keep the panel's optional runtime download working;
# tini reaps the anytls-server children so the container stops cleanly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    PORT=8080 \
    ANYTLS_GATEWAY_PORT=8443 \
    ANYTLS_VERSION=v0.0.13 \
    DATA_DIR=/data \
    ANYTLS_SERVER_BIN=/usr/local/bin/anytls-server

WORKDIR /app

# Production dependencies only.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

# Built assets and service binaries
COPY --from=build /app/dist ./dist
COPY --from=build /app/index.html ./index.html
COPY --from=core-bin /out/anytls-server /usr/local/bin/anytls-server

# Support files used by the diagnostics view and the legacy Ubuntu ZIP feature.
COPY server.ts install.sh ./
COPY bin ./bin

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p /data /app/vendor

# The container deliberately runs as root: Railway mounts volumes owned by root,
# and the panel must be able to create its data directory on any mount.
# 8080 / 3000 = web panel listeners.
# 8443 = public AnyTLS port — expose it with a Railway TCP Proxy.
EXPOSE 8080 3000 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "dist/server.cjs"]