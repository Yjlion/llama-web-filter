#!/usr/bin/env bash
# scripts/package-release.sh - cross-compile every release target and bundle
# each into the archive a GitHub release would attach (the same thing
# .goreleaser.yaml does in CI, for building locally).
#
# Usage: ./scripts/package-release.sh [VERSION] [OUT_DIR]
#   VERSION  embedded via -ldflags and used in archive names
#            (default: `git describe --tags --always --dirty`, or "dev")
#   OUT_DIR  where to write archives (default: ./dist)
#
# The binary is static (CGO_ENABLED=0). The llama.cpp runtime and the model
# are downloaded on first run by `webfilter setup`, not bundled.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT_DIR="${2:-$REPO_ROOT/dist}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X github.com/yjlion/llama-web-filter/internal/version.Version=${VERSION}"
LDFLAGS="$LDFLAGS -X github.com/yjlion/llama-web-filter/internal/version.Commit=${COMMIT}"
LDFLAGS="$LDFLAGS -X github.com/yjlion/llama-web-filter/internal/version.BuildDate=${BUILD_DATE}"

# goos:goarch:binary-extension
TARGETS=(
  "windows:amd64:.exe"
  "windows:arm64:.exe"
  "linux:amd64:"
  "linux:arm64:"
  "darwin:amd64:"
  "darwin:arm64:"
)

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for target in "${TARGETS[@]}"; do
  IFS=: read -r goos goarch ext <<<"$target"
  name="webfilter-${VERSION}-${goos}-${goarch}"
  stage="$OUT_DIR/$name"
  mkdir -p "$stage/config" "$stage/policies" "$stage/docs"

  echo "[package] building ${goos}/${goarch} ..."
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath \
    -ldflags "$LDFLAGS" \
    -o "$stage/webfilter${ext}" ./cmd/webfilter

  cp config/settings.example.json "$stage/config/"
  cp policies/default.json.example "$stage/policies/"
  cp README.md LICENSE "$stage/"
  cp docs/install.md docs/llm.md docs/policies.md "$stage/docs/"

  if [[ "$goos" == "windows" ]]; then
    (cd "$OUT_DIR" && zip -qr "$name.zip" "$name")
  else
    tar -C "$OUT_DIR" -czf "$OUT_DIR/$name.tar.gz" "$name"
  fi
  rm -rf "$stage"
done

(cd "$OUT_DIR" && sha256sum ./*.tar.gz ./*.zip > checksums.txt)
echo "[package] done: $OUT_DIR"
ls -la "$OUT_DIR"
