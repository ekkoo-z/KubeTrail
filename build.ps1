$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = Join-Path $Root "apps/agent"
$DesktopDir = Join-Path $Root "apps/desktop"
$DesktopBin = Join-Path $DesktopDir "build/bin"
$AppBundle = Join-Path $DesktopBin "kubetrail.app"

function Install-NodeDeps {
  param([Parameter(Mandatory = $true)][string]$Path)

  Push-Location $Path
  try {
    if (Test-Path "package-lock.json") {
      npm ci --include=dev
    } else {
      npm install
    }
  } finally {
    Pop-Location
  }
}

function Get-DesktopLayout {
  $appContents = Join-Path $AppBundle "Contents"
  if (Test-Path $appContents) {
    return @{
      ResourceDir = Join-Path $appContents "Resources"
      AgentContextRoot = $appContents
      RuntimeCheckRoot = $appContents
    }
  }

  return @{
    ResourceDir = $DesktopBin
    AgentContextRoot = Join-Path $DesktopDir "build"
    RuntimeCheckRoot = Join-Path $DesktopDir "build"
  }
}

function Copy-OptionalDirectoryContents {
  param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination
  )

  if (-not (Test-Path $Source)) {
    return
  }

  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  Get-ChildItem -Path $Source -Force | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $Destination -Recurse -Force
  }
}

function Remove-DesktopRuntimeArtifacts {
  $layout = Get-DesktopLayout
  if (-not (Test-Path $layout.RuntimeCheckRoot)) {
    return
  }

  $paths = @(
    (Join-Path $layout.RuntimeCheckRoot ".runtime"),
    (Join-Path $layout.RuntimeCheckRoot "exp/generated"),
    (Join-Path $layout.ResourceDir "codex")
  )

  foreach ($path in $paths) {
    if (Test-Path $path) {
      Remove-Item -Recurse -Force $path
    }
  }
}

function Test-DesktopRuntimeArtifacts {
  $layout = Get-DesktopLayout
  if (-not (Test-Path $layout.RuntimeCheckRoot)) {
    return
  }

  $found = @()
  $items = Get-ChildItem -Path $layout.RuntimeCheckRoot -Recurse -Force -ErrorAction SilentlyContinue
  foreach ($item in $items) {
    $fullName = $item.FullName
    if (
      $item.Name -eq ".runtime" -or
      $fullName -like "*claude*projects*" -or
      $item.Name -like "*.jsonl" -or
      $item.Name -eq "tool-results" -or
      $fullName -like "*exp*generated*"
    ) {
      $found += $fullName
    }
  }

  if ($found.Count -gt 0) {
    foreach ($path in $found) {
      Write-Error "runtime artifact must not be embedded in app bundle: $path"
    }
    throw "store agent runtime logs and generated EXP bundles under KUBETRAIL_AGENT_RUNTIME_DIR instead."
  }
}

Write-Host "==> Installing agent dependencies..."
Install-NodeDeps $AgentDir

Write-Host "==> Bundling agent..."
Push-Location $AgentDir
try {
  npx --no-install esbuild src/cli.ts --bundle --platform=node --format=esm --outfile=dist/agent-bundle.mjs --external:better-sqlite3
} finally {
  Pop-Location
}

Write-Host "==> Removing stale runtime artifacts from previous desktop builds..."
Remove-DesktopRuntimeArtifacts

Write-Host "==> Building desktop app..."
Push-Location $DesktopDir
try {
  wails build
} finally {
  Pop-Location
}

Remove-DesktopRuntimeArtifacts
$layout = Get-DesktopLayout

Write-Host "==> Embedding agent bundle..."
New-Item -ItemType Directory -Force -Path $layout.ResourceDir | Out-Null
Copy-Item -Force (Join-Path $AgentDir "dist/agent-bundle.mjs") (Join-Path $layout.ResourceDir "agent-bundle.mjs")

Write-Host "==> Claude CLI is not embedded; desktop runtime will discover claude from PATH..."
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $layout.ResourceDir "claude")
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $layout.ResourceDir "claude.exe")

Write-Host "==> Codex CLI is not embedded; desktop runtime will discover codex from PATH..."
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $layout.ResourceDir "codex")

Write-Host "==> Embedding agent project context..."
New-Item -ItemType Directory -Force -Path $layout.AgentContextRoot | Out-Null
$claudeMd = Join-Path $AgentDir "CLAUDE.md"
if (Test-Path $claudeMd) {
  Copy-Item -Force $claudeMd (Join-Path $layout.AgentContextRoot "CLAUDE.md")
}
Copy-OptionalDirectoryContents (Join-Path $AgentDir ".claude") (Join-Path $layout.AgentContextRoot ".claude")
Copy-OptionalDirectoryContents (Join-Path $AgentDir "exp/assets") (Join-Path $layout.AgentContextRoot "exp/assets")

Write-Host "==> Checking app bundle for runtime data leakage..."
Test-DesktopRuntimeArtifacts

Write-Host "==> Done: $DesktopBin"
