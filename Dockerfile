# llama-web-filter - example container image.
#
# The proxy and the SQLite log store are pure Go, so this builds with
# CGO_ENABLED=0. The LLM runtime (llama-server) and model are downloaded at
# first run into the data volume. See docs/docker.md for the walkthrough.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM golang:1.26-alpine AS build

# Version metadata, matching what scripts/package-release.sh stamps in, so an
# image built from a release tag reports the same string as the tarball:
#   docker build --build-arg VERSION=v1.2.3 --build-arg COMMIT=$(git rev-parse --short HEAD) .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

# Dependencies first so an edit to the source doesn't re-download the module
# cache on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags="-s -w \
        -X github.com/yjlion/llama-web-filter/internal/version.Version=${VERSION} \
        -X github.com/yjlion/llama-web-filter/internal/version.Commit=${COMMIT} \
        -X github.com/yjlion/llama-web-filter/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/webfilter ./cmd/webfilter

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM alpine:3.24

# ca-certificates is not optional: the engine fetches upstream sites over TLS
# and verifies them against the system root store. On a `scratch`/rootless
# image with no roots, every https:// fetch through the proxy fails.
# wget (busybox) is what HEALTHCHECK below uses.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 1000 webfilter \
 && adduser -S -u 1000 -G webfilter -h /data webfilter

COPY --from=build /out/webfilter /usr/local/bin/webfilter

# /data is created and chowned here so a *named* volume mounted over it
# inherits this ownership from the image, and the non-root user can write
# certs/, logs/ and policies/ without a manual chown on the host.
RUN mkdir -p /data && chown webfilter:webfilter /data

USER webfilter
WORKDIR /data
VOLUME ["/data"]

# 8080 HTTP(S) forward proxy, 1080 SOCKS5, 8000 management UI + API.
# Note the bootstrap settings bind SOCKS5 to `socks5@127.0.0.1:1080` - i.e.
# loopback inside the container - so publishing 1080 does nothing until that
# entry is changed to 0.0.0.0. The proxy and management binds are 0.0.0.0
# already. Keep proxy_listen / mgmt_port and the published ports in step.
EXPOSE 8080 1080 8000

# Deliberately NOT copying config/settings.example.json into the image.
# That file pins 127.0.0.1:8080 and mgmt_host 127.0.0.1 with CWD-relative
# ./certs etc., so a container seeded from it would publish ports that serve
# nothing. Instead, letting config.BootstrapRuntimeFiles generate the file on
# first start gives 0.0.0.0 binds and *absolute* directory paths rooted at
# /data (it strips the trailing "config" component of --settings), which is
# exactly what a single mounted volume wants.
ENTRYPOINT ["/usr/local/bin/webfilter"]
CMD ["run", "--settings", "/data/config/settings.json"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8000/api/version || exit 1
