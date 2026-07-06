#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-"$ROOT_DIR/dist"}"
PKG="${PKG:-./cmd/kubetrail-server}"
BIN_NAME="${BIN_NAME:-kubetrail-server}"
VERSION="${VERSION:-dev}"
UPX_MODE="${UPX_MODE:-auto}"
UPX_FLAGS="${UPX_FLAGS:---best --lzma}"
SKIP_TESTS="${SKIP_TESTS:-0}"

# Format: GOOS/GOARCH[/GOARM]. Override with:
#   TARGETS="linux/amd64 linux/arm64 darwin/arm64" ./scripts/build-release.sh
TARGETS="${TARGETS:-linux/amd64 linux/arm64 linux/arm/7 linux/386 linux/ppc64le linux/s390x linux/riscv64 linux/loong64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"

if [[ "$VERSION" == *"/"* || "$VERSION" == *"\\"* || "$VERSION" == *$'\n'* || "$VERSION" == *$'\r'* ]]; then
  echo "error: VERSION must not contain path separators or newlines" >&2
  exit 2
fi

case "$UPX_MODE" in
  auto|always|never) ;;
  *)
    echo "error: UPX_MODE must be one of: auto, always, never" >&2
    exit 2
    ;;
esac

if ! command -v go >/dev/null 2>&1; then
  echo "error: go not found in PATH" >&2
  exit 2
fi

if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  echo "error: shasum or sha256sum is required" >&2
  exit 2
fi

if [[ "$UPX_MODE" == "always" ]] && ! command -v upx >/dev/null 2>&1; then
  echo "error: UPX_MODE=always but upx was not found in PATH" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/"$BIN_NAME"-* "$OUT_DIR"/SHA256SUMS

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kubetrail-release-build.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

export CGO_ENABLED=0

COMMON_FLAGS=(
  -trimpath
  -buildvcs=false
  -mod=readonly
  -ldflags "-s -w -buildid= -X github.com/ekkoo-z/KubeTrail/internal/command.version=$VERSION"
)

TEST_PKGS="${TEST_PKGS:-./cmd/... ./internal/...}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$1" | awk '{print $1}'
}

leak_check() {
  local binary="$1"
  local failed=0
  local needles=("$ROOT_DIR")

  if [[ -n "${HOME:-}" && "${HOME:-}" != "/" ]]; then
    needles+=("$HOME")
  fi

  if ! command -v strings >/dev/null 2>&1; then
    echo "warning: strings not found; skipped local path leakage check" >&2
    return 0
  fi

  for needle in "${needles[@]}"; do
    if [[ -n "$needle" ]] && strings "$binary" | grep -F -- "$needle" >/dev/null; then
      echo "error: local path leaked into $binary: $needle" >&2
      failed=1
    fi
  done

  return "$failed"
}

assert_no_go_buildinfo_vcs() {
  local binary="$1"
  local info
  info="$(go version -m "$binary" 2>/dev/null || true)"
  if grep -E '^\s+build\s+vcs=' <<<"$info" >/dev/null; then
    echo "error: VCS metadata leaked into $(basename "$binary")" >&2
    echo "$info" >&2
    return 1
  fi
}

upx_available() {
  [[ "$UPX_MODE" != "never" ]] && command -v upx >/dev/null 2>&1
}

finish_artifact() {
  local raw="$1"
  local output="$2"
  local suffix="$3"
  local before_size after_size

  before_size="$(wc -c <"$raw" | tr -d ' ')"

  if upx_available; then
    echo "==> upx compressing $suffix"
    if upx $UPX_FLAGS -q -o "$output" "$raw"; then
      upx -q -t "$output" >/dev/null
      leak_check "$output"
      after_size="$(wc -c <"$output" | tr -d ' ')"
      printf "%s  %s\n" "$(sha256_file "$output")" "$(basename "$output")" >>"$OUT_DIR/SHA256SUMS"
      return
    fi

    if [[ "$UPX_MODE" == "always" ]]; then
      echo "error: upx failed for $suffix" >&2
      exit 1
    fi

    echo "warning: upx failed for $suffix; keeping uncompressed artifact" >&2
  elif [[ "$UPX_MODE" == "auto" ]]; then
    echo "==> upx not found; keeping $suffix uncompressed"
  fi

  cp "$raw" "$output"
  leak_check "$output"
  after_size="$(wc -c <"$output" | tr -d ' ')"
  printf "%s  %s\n" "$(sha256_file "$output")" "$(basename "$output")" >>"$OUT_DIR/SHA256SUMS"
}

build_target() {
  local target="$1"
  local goos goarch goarm suffix raw output

  IFS=/ read -r goos goarch goarm <<<"$target"
  suffix="${goos}-${goarch}"
  if [[ -n "${goarm:-}" ]]; then
    suffix="${suffix}v${goarm}"
  fi
  raw="$TMP_DIR/$BIN_NAME-$suffix.unpacked"
  output="$OUT_DIR/$BIN_NAME-$suffix"
  if [[ "$goos" == "windows" ]]; then
    output="$output.exe"
  fi

  echo "==> building $target"
  env GOOS="$goos" GOARCH="$goarch" GOARM="${goarm:-}" \
    go build "${COMMON_FLAGS[@]}" -o "$raw" "$PKG"

  leak_check "$raw"
  assert_no_go_buildinfo_vcs "$raw"
  finish_artifact "$raw" "$output" "$suffix"
}

main() {
  cd "$ROOT_DIR"

  if [[ "$SKIP_TESTS" != "1" ]]; then
    go test $TEST_PKGS
  fi

  for target in $TARGETS; do
    build_target "$target"
  done

  echo
  echo "built artifacts:"
  sed 's/^/  /' "$OUT_DIR/SHA256SUMS"
}

main "$@"
