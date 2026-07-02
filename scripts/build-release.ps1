$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Resolve-Path (Join-Path $ScriptDir "..")
$OutDir = if ($env:OUT_DIR) { $env:OUT_DIR } else { Join-Path $RootDir "dist" }
$Pkg = if ($env:PKG) { $env:PKG } else { "./cmd/kubetrail-server" }
$BinName = if ($env:BIN_NAME) { $env:BIN_NAME } else { "kubetrail-server" }
$Version = if ($env:VERSION) { $env:VERSION } else { "dev" }
$TargetsText = if ($env:TARGETS) {
  $env:TARGETS
} else {
  "linux/amd64 linux/arm64 linux/arm/7 linux/386 linux/ppc64le linux/s390x linux/riscv64 linux/loong64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
}
$TestPkgsText = if ($env:TEST_PKGS) { $env:TEST_PKGS } else { "./cmd/... ./internal/..." }
$OriginalGoos = $env:GOOS
$OriginalGoarch = $env:GOARCH
$OriginalGoarm = $env:GOARM

if ($Version.Contains("/") -or $Version.Contains("\")) {
  throw "VERSION must not contain path separators"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Get-ChildItem -Path $OutDir -File -Filter "$BinName-*" -ErrorAction SilentlyContinue | Remove-Item -Force
$shaFile = Join-Path $OutDir "SHA256SUMS"
Remove-Item -Force -ErrorAction SilentlyContinue $shaFile

$env:CGO_ENABLED = "0"

function Invoke-Go {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)

  & go @Args
  if ($LASTEXITCODE -ne 0) {
    throw "go $($Args -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Test-PathLeak {
  param([Parameter(Mandatory = $true)][string]$Binary)

  $strings = Get-Command strings -ErrorAction SilentlyContinue
  if (-not $strings) {
    Write-Warning "strings not found; skipped local path leakage check"
    return
  }

  $needles = @("$RootDir")
  if ($env:HOME -and $env:HOME -ne "/") {
    $needles += $env:HOME
  }
  if ($env:USERPROFILE) {
    $needles += $env:USERPROFILE
  }

  $content = & strings $Binary
  foreach ($needle in $needles) {
    if ($needle -and ($content | Select-String -SimpleMatch $needle -Quiet)) {
      throw "local path leaked into ${Binary}: $needle"
    }
  }
}

function Build-Target {
  param([Parameter(Mandatory = $true)][string]$Target)

  $parts = $Target.Split("/")
  $goos = $parts[0]
  $goarch = $parts[1]
  $goarm = if ($parts.Count -gt 2) { $parts[2] } else { "" }
  $suffix = "${goos}-${goarch}"
  if ($goarm) {
    $suffix = "${suffix}v${goarm}"
  }

  $output = Join-Path $OutDir "${BinName}-${suffix}"
  if ($goos -eq "windows") {
    $output = "$output.exe"
  }

  Write-Host "==> building $Target"
  $env:GOOS = $goos
  $env:GOARCH = $goarch
  $env:GOARM = $goarm

  $buildArgs = @(
    "build",
    "-trimpath",
    "-buildvcs=false",
    "-ldflags",
    "-s -w -buildid= -X github.com/ekkoo-z/KubeTrail/internal/command.version=$Version",
    "-o",
    $output,
    $Pkg
  )
  Invoke-Go @buildArgs
  Test-PathLeak $output

  $hash = (Get-FileHash -Algorithm SHA256 $output).Hash.ToLowerInvariant()
  Add-Content -Path $shaFile -Value "$hash  $(Split-Path -Leaf $output)"
}

Push-Location $RootDir
try {
  $testPkgs = $TestPkgsText.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
  Invoke-Go @(@("test") + $testPkgs)

  $targets = $TargetsText.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
  foreach ($target in $targets) {
    Build-Target $target
  }

  Write-Host ""
  Write-Host "built artifacts:"
  Get-Content $shaFile | ForEach-Object { Write-Host "  $_" }
} finally {
  Pop-Location
  if ($null -eq $OriginalGoos) { Remove-Item Env:\GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $OriginalGoos }
  if ($null -eq $OriginalGoarch) { Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $OriginalGoarch }
  if ($null -eq $OriginalGoarm) { Remove-Item Env:\GOARM -ErrorAction SilentlyContinue } else { $env:GOARM = $OriginalGoarm }
}
