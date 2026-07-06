#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="$ROOT/apps/agent"
DESKTOP_DIR="$ROOT/apps/desktop"
DESKTOP_BIN="$DESKTOP_DIR/build/bin"
APP_BUNDLE="$DESKTOP_BIN/kubetrail.app"

install_node_deps() {
  local dir="$1"
  cd "$dir"
  if [ -f package-lock.json ]; then
    npm ci --include=dev
  else
    npm install
  fi
}

resolve_desktop_layout() {
  if [ -d "$APP_BUNDLE/Contents" ]; then
    RESOURCE_DIR="$APP_BUNDLE/Contents/Resources"
    AGENT_CONTEXT_ROOT="$RESOURCE_DIR/agent-context"
    RUNTIME_CHECK_ROOT="$APP_BUNDLE/Contents"
  else
    RESOURCE_DIR="$DESKTOP_BIN"
    AGENT_CONTEXT_ROOT="$RESOURCE_DIR/agent-context"
    RUNTIME_CHECK_ROOT="$DESKTOP_DIR/build"
  fi
}

copy_optional_dir_contents() {
  local src="$1"
  local dst="$2"

  if [ ! -d "$src" ]; then
    return
  fi

  mkdir -p "$dst"
  cp -R "$src/." "$dst/"
}

cleanup_desktop_runtime_artifacts() {
  resolve_desktop_layout
  if [ ! -d "$RUNTIME_CHECK_ROOT" ]; then
    return
  fi

  rm -rf \
    "$RUNTIME_CHECK_ROOT/.runtime" \
    "$RUNTIME_CHECK_ROOT/.claude" \
    "$RUNTIME_CHECK_ROOT/.agents" \
    "$RUNTIME_CHECK_ROOT/CLAUDE.md" \
    "$RUNTIME_CHECK_ROOT/exp/assets" \
    "$RUNTIME_CHECK_ROOT/exp/generated" \
    "$RESOURCE_DIR/agent-context" \
    "$RESOURCE_DIR/codex"
}

sign_desktop_app() {
  if [ ! -d "$APP_BUNDLE/Contents" ]; then
    return
  fi
  if ! command -v codesign >/dev/null 2>&1; then
    echo "==> codesign not found; skipping final app signature refresh"
    return
  fi
  echo "==> Refreshing app signature after embedding agent resources..."
  codesign --force --deep --sign - "$APP_BUNDLE"
}

check_desktop_runtime_artifacts() {
  resolve_desktop_layout
  if [ ! -d "$RUNTIME_CHECK_ROOT" ]; then
    return
  fi

  local found=0
  while IFS= read -r -d '' path; do
    echo "ERROR: runtime artifact must not be embedded in app bundle: $path" >&2
    found=1
  done < <(
    find "$RUNTIME_CHECK_ROOT" \
      \( -name ".runtime" -o -path "*/claude/projects" -o -name "*.jsonl" -o -name "tool-results" -o -path "*/exp/generated" \) \
      -print0
  )

  if [ "$found" -ne 0 ]; then
    echo "ERROR: store agent runtime logs and generated EXP bundles under KUBETRAIL_AGENT_RUNTIME_DIR instead." >&2
    return 1
  fi
}

echo "==> Installing agent dependencies..."
install_node_deps "$AGENT_DIR"

echo "==> Bundling agent..."
cd "$AGENT_DIR"
npx --no-install esbuild src/cli.ts --bundle --platform=node --format=esm \
  --outfile=dist/agent-bundle.mjs --external:better-sqlite3 --log-level=warning

echo "==> Removing stale runtime artifacts from previous desktop builds..."
cleanup_desktop_runtime_artifacts

echo "==> Building desktop app..."
cd "$DESKTOP_DIR"
wails build

cleanup_desktop_runtime_artifacts

resolve_desktop_layout

echo "==> Embedding agent bundle..."
mkdir -p "$RESOURCE_DIR"
cp "$AGENT_DIR/dist/agent-bundle.mjs" "$RESOURCE_DIR/"

echo "==> Claude CLI is not embedded; desktop runtime will discover claude from PATH..."
rm -f "$RESOURCE_DIR/claude" "$RESOURCE_DIR/claude.exe"

echo "==> Codex CLI is not embedded; desktop runtime will discover codex from PATH..."
rm -rf "$RESOURCE_DIR/codex"

echo "==> Embedding agent project context..."
mkdir -p "$AGENT_CONTEXT_ROOT"
if [ -f "$AGENT_DIR/CLAUDE.md" ]; then
  cp "$AGENT_DIR/CLAUDE.md" "$AGENT_CONTEXT_ROOT/CLAUDE.md"
fi
if [ -f "$AGENT_DIR/AGENTS.md" ]; then
  cp "$AGENT_DIR/AGENTS.md" "$AGENT_CONTEXT_ROOT/AGENTS.md"
fi
copy_optional_dir_contents "$AGENT_DIR/.claude" "$AGENT_CONTEXT_ROOT/claude"
copy_optional_dir_contents "$AGENT_DIR/exp/assets" "$AGENT_CONTEXT_ROOT/exp/assets"
find "$AGENT_CONTEXT_ROOT" -name ".DS_Store" -type f -delete

echo "==> Checking app bundle for runtime data leakage..."
check_desktop_runtime_artifacts

sign_desktop_app

echo "==> Done: $DESKTOP_BIN"
