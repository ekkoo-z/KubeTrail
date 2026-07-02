#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-"$ROOT_DIR/dist-secure"}"
PKG="${PKG:-./cmd/kubetrail-server}"
BIN_NAME="${BIN_NAME:-kubetrail-server}"
VERSION="${VERSION:-release}"
TARGETS="${TARGETS:-linux/amd64}"
UPX_FLAGS="${UPX_FLAGS:---best --lzma}"
SKIP_TESTS="${SKIP_TESTS:-0}"

if [[ "$VERSION" == *"/"* || "$VERSION" == *"\\"* || "$VERSION" == *$'\n'* || "$VERSION" == *$'\r'* ]]; then
  echo "error: VERSION must not contain path separators or newlines" >&2
  exit 2
fi

if ! command -v go >/dev/null 2>&1; then
  echo "error: go not found in PATH" >&2
  exit 2
fi

if ! command -v upx >/dev/null 2>&1; then
  echo "error: upx not found in PATH" >&2
  echo "install it first, for example: brew install upx" >&2
  exit 2
fi

if ! command -v strings >/dev/null 2>&1; then
  echo "error: strings not found in PATH; cannot run leakage checks" >&2
  exit 2
fi

if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  echo "error: shasum or sha256sum is required" >&2
  exit 2
fi

umask 077
mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/"$BIN_NAME"-* "$OUT_DIR"/SHA256SUMS

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kubetrail-secure-build.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

export CGO_ENABLED=0
export GOFLAGS="${GOFLAGS:-}"

COMMON_FLAGS=(
  -trimpath
  -buildvcs=false
  -mod=readonly
  -ldflags "-s -w -buildid= -X github.com/ekkoo-z/KubeTrail/internal/command.version=$VERSION"
)

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$1" | awk '{print $1}'
}

collect_sensitive_env_names() {
  env | awk -F= '
    length($2) >= 8 &&
    $1 ~ /(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API_KEY|ACCESS_KEY|AUTH|COOKIE|KUBECONFIG|ANTHROPIC|OPENAI|AWS|GCP|GOOGLE|AZURE|ALI|OSS)/ {
      print $1
    }'
}

scan_exact_secret_value() {
  local binary="$1"
  local name="$2"
  local value="${!name:-}"

  if [[ -z "$value" || ${#value} -lt 8 ]]; then
    return 0
  fi
  if strings -a "$binary" | grep -F -- "$value" >/dev/null; then
    echo "error: sensitive env value leaked into $(basename "$binary"): $name" >&2
    return 1
  fi
}

leak_check() {
  local binary="$1"
  local failed=0
  local needles=("$ROOT_DIR")

  if [[ -n "${HOME:-}" && "${HOME:-}" != "/" ]]; then
    needles+=("$HOME")
  fi
  if [[ -n "${USER:-}" && ${#USER} -ge 3 ]]; then
    needles+=("$USER")
  fi
  if [[ -n "${TMPDIR:-}" ]]; then
    needles+=("${TMPDIR%/}")
  fi

  for needle in "${needles[@]}"; do
    if [[ -n "$needle" ]] && strings -a "$binary" | grep -F -- "$needle" >/dev/null; then
      echo "error: local identifier leaked into $(basename "$binary"): $needle" >&2
      failed=1
    fi
  done

  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if ! scan_exact_secret_value "$binary" "$name"; then
      failed=1
    fi
  done < <(collect_sensitive_env_names)

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

build_target() {
  local target="$1"
  local goos goarch goarm suffix raw output before_size after_size

  IFS=/ read -r goos goarch goarm <<<"$target"
  suffix="${goos}-${goarch}"
  if [[ -n "${goarm:-}" ]]; then
    suffix="${suffix}v${goarm}"
  fi

  raw="$TMP_DIR/$BIN_NAME-$suffix.unpacked"
  output="$OUT_DIR/$BIN_NAME-$suffix"

  echo "==> building $target"
  env GOOS="$goos" GOARCH="$goarch" GOARM="${goarm:-}" \
    go build "${COMMON_FLAGS[@]}" -o "$raw" "$PKG"

  leak_check "$raw"
  assert_no_go_buildinfo_vcs "$raw"

  before_size="$(wc -c <"$raw" | tr -d ' ')"
  echo "==> upx compressing $suffix"
  # shellcheck disable=SC2086
  upx $UPX_FLAGS -q -o "$output" "$raw"
  upx -q -t "$output" >/dev/null
  chmod 0700 "$output"

  leak_check "$output"
  after_size="$(wc -c <"$output" | tr -d ' ')"
  printf "%s  %s\n" "$(sha256_file "$output")" "$(basename "$output")" >>"$OUT_DIR/SHA256SUMS"
}

main() {
  cd "$ROOT_DIR"

  if [[ "$SKIP_TESTS" != "1" ]]; then
    go test ./...
  fi

  for target in $TARGETS; do
    build_target "$target"
  done

  echo
  echo "built compressed artifacts:"
  sed 's/^/  /' "$OUT_DIR/SHA256SUMS"
}

main "$@"
