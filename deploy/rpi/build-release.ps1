# ---------------------------------------------------------------------------
# build-release.ps1 -- PowerShell port of build-release.sh for Windows hosts.
#
# Cross-compiles the Go agent for linux/arm64, builds the Astro panel and
# packs everything into a tar.gz that install.sh (on the Pi) consumes.
#
# Works in Windows PowerShell 5.1 (pwsh.exe also OK). Requires:
#   - Go 1.23+                (https://go.dev/dl/)
#   - Node.js 20+ and npm     (https://nodejs.org/)
#   - tar.exe                 (ships with Windows 10 1803+ as bsdtar)
#   - git (optional, used only to derive the version string)
#
# Layout assumed:
#     <root>\rud1-fw       - this repo (script lives in deploy\rpi\)
#     <root>\rud1-app      - sibling repo with the Astro panel
#
# Override with -AppDir, -GoArch, or -OutDir. Examples:
#     .\deploy\rpi\build-release.ps1
#     .\deploy\rpi\build-release.ps1 -GoArch arm           # 32-bit Pi OS
#     .\deploy\rpi\build-release.ps1 -AppDir D:\code\rud1-app
#     .\deploy\rpi\build-release.ps1 -SkipUI               # agent-only
#
# Output:
#     deploy\rpi\dist\rud1-release-<version>-linux-<arch>.tar.gz
#     deploy\rpi\dist\rud1-release-<version>-linux-<arch>.tar.gz.sha256
#
# NOTE on executable bits: bsdtar on Windows cannot carry POSIX +x from NTFS,
# so the install.sh / uninstall.sh inside the tarball end up as 0644. The
# README deploys them with `sudo bash install.sh` to sidestep that -- do NOT
# rely on ./install.sh being directly executable after extraction.
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$AppDir = $env:RUD1_APP_DIR,
    [ValidateSet("arm64","arm")] [string]$GoArch = "arm64",
    [string]$OutDir,
    [switch]$SkipUI
)

$ErrorActionPreference = "Stop"

# --- Helpers -----------------------------------------------------------------
function Write-Step ($msg) { Write-Host "-> $msg" -ForegroundColor Cyan }
function Write-Warn ($msg) { Write-Host "!! $msg" -ForegroundColor Yellow }
function Write-Err  ($msg) { Write-Host "xx $msg" -ForegroundColor Red; exit 1 }

function Test-Cmd ($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Err "$name is required -- $hint"
    }
}

# --- Locate paths ------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$FwRoot    = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
if (-not $OutDir) { $OutDir = Join-Path $ScriptDir "dist" }
$StageDir  = Join-Path $OutDir ".stage"

if (-not $AppDir) {
    $candidate = Join-Path $FwRoot "..\rud1-app"
    if (Test-Path $candidate) {
        $AppDir = (Resolve-Path $candidate).Path
    }
}

if ($SkipUI) { $AppDir = "" }

if (-not $AppDir -or -not (Test-Path $AppDir)) {
    Write-Warn "rud1-app not found (looked at -AppDir / `$env:RUD1_APP_DIR / ..\rud1-app)."
    Write-Warn "Only the agent binary + config will be included. Pass -AppDir to bundle the UI."
    $AppDir = ""
}

# --- Tooling -----------------------------------------------------------------
Test-Cmd "go"  "install Go 1.23+ from https://go.dev/dl/"
Test-Cmd "tar" "needs Windows 10 1803+ (built-in bsdtar)"
if ($AppDir) { Test-Cmd "npm" "install Node.js 20+ from https://nodejs.org/" }

$GoOS = "linux"

# Version string -- git describe if available, otherwise "dev".
$Version = "dev"
$Commit  = "none"
if (Get-Command git -ErrorAction SilentlyContinue) {
    Push-Location $FwRoot
    try {
        $v = (& git describe --tags --always --dirty 2>$null)
        if ($LASTEXITCODE -eq 0 -and $v) { $Version = $v.Trim() }
        $c = (& git rev-parse --short HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $c) { $Commit = $c.Trim() }
    } finally { Pop-Location }
}
$BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$Tarball   = Join-Path $OutDir "rud1-release-$Version-$GoOS-$GoArch.tar.gz"

# --- Clean stage -------------------------------------------------------------
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
foreach ($d in "bin","web","systemd","nginx","modules","sysctl","config") {
    New-Item -ItemType Directory -Force -Path (Join-Path $StageDir $d) | Out-Null
}

# --- Build agent -------------------------------------------------------------
Write-Step "Building rud1-agent $Version for $GoOS/$GoArch"
$BinOut = Join-Path $StageDir "bin\rud1-agent"

# Stash + restore env so we don't pollute the user's shell.
$prevCgo  = $env:CGO_ENABLED
$prevOS   = $env:GOOS
$prevArch = $env:GOARCH
try {
    $env:CGO_ENABLED = "0"
    $env:GOOS        = $GoOS
    $env:GOARCH      = $GoArch
    Push-Location $FwRoot
    try {
        $ldflags = "-s -w -X main.Version=$Version -X main.Commit=$Commit -X main.BuildDate=$BuildDate"
        & go build -trimpath -ldflags $ldflags -o $BinOut ./cmd/rud1-agent
        if ($LASTEXITCODE -ne 0) { Write-Err "go build failed" }
    } finally { Pop-Location }
} finally {
    $env:CGO_ENABLED = $prevCgo
    $env:GOOS        = $prevOS
    $env:GOARCH      = $prevArch
}
if (-not (Test-Path $BinOut)) { Write-Err "agent binary was not produced" }

# --- Build web UI ------------------------------------------------------------
if ($AppDir) {
    Write-Step "Building rud1-app (Astro static output)"
    Push-Location $AppDir
    try {
        if (-not (Test-Path (Join-Path $AppDir "node_modules"))) {
            # On Windows npm is npm.cmd -- call via cmd /c for proper PATH handling.
            & cmd /c "npm install --no-audit --no-fund"
            if ($LASTEXITCODE -ne 0) { Write-Err "npm install failed" }
        }
        & cmd /c "npm run build"
        if ($LASTEXITCODE -ne 0) { Write-Err "npm run build failed" }
    } finally { Pop-Location }

    $appDist = Join-Path $AppDir "dist"
    if (-not (Test-Path $appDist)) { Write-Err "rud1-app build did not produce a dist\ folder" }
    Copy-Item -Recurse -Force "$appDist\*" (Join-Path $StageDir "web")
    New-Item -ItemType File -Force -Path (Join-Path $StageDir "web\.has-ui") | Out-Null
} else {
    $fallback = '<!doctype html><meta charset="utf-8"><title>Rud1</title><h1>Rud1 agent</h1><p>Web UI not bundled. Access the API at :7070.</p>'
    Set-Content -Encoding utf8 -NoNewline -Path (Join-Path $StageDir "web\index.html") -Value $fallback
}

# --- Copy install assets -----------------------------------------------------
Write-Step "Copying install assets"
$Assets = @{
    "install.sh"                        = "install.sh"
    "uninstall.sh"                      = "uninstall.sh"
    "assets\rud1-agent.service"         = "systemd\rud1-agent.service"
    "assets\rud1.nginx.conf"            = "nginx\rud1"
    "assets\rud1-modules.conf"          = "modules\rud1.conf"
    "assets\rud1-sysctl.conf"           = "sysctl\99-rud1.conf"
    "assets\config.yaml.template"       = "config\config.yaml.template"
}
foreach ($src in $Assets.Keys) {
    $from = Join-Path $ScriptDir $src
    $to   = Join-Path $StageDir  $Assets[$src]
    if (-not (Test-Path $from)) { Write-Err "missing asset: $src" }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
    Copy-Item -Force $from $to
}

# Version manifest consumed by install.sh
$hasWeb = if ($AppDir) { "yes" } else { "no" }
$manifest = @"
version=$Version
commit=$Commit
build_date=$BuildDate
goos=$GoOS
goarch=$GoArch
has_web=$hasWeb
"@
Set-Content -Encoding utf8 -Path (Join-Path $StageDir "VERSION") -Value $manifest

# --- Pack --------------------------------------------------------------------
Write-Step "Packing $Tarball"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (Test-Path $Tarball)          { Remove-Item -Force $Tarball }
if (Test-Path "$Tarball.sha256") { Remove-Item -Force "$Tarball.sha256" }

# bsdtar (Windows tar.exe) does not support --owner/--group; install.sh runs
# as root and copies files into place, so the tar entries' uid/gid don't
# matter for the final on-Pi state.
& tar -C $StageDir -czf $Tarball "."
if ($LASTEXITCODE -ne 0) { Write-Err "tar failed" }

# SHA256 sidecar -- match the `sha256sum` line format (<hash>  <filename>).
$hash = (Get-FileHash -Algorithm SHA256 $Tarball).Hash.ToLower()
$base = Split-Path -Leaf $Tarball
Set-Content -Encoding ascii -Path "$Tarball.sha256" -Value "$hash  $base"

$sizeBytes = (Get-Item $Tarball).Length
if ($sizeBytes -ge 1MB) {
    $sizeStr = "{0:N1} MB" -f ($sizeBytes / 1MB)
} else {
    $sizeStr = "{0:N1} KB" -f ($sizeBytes / 1KB)
}

Write-Step "Done."
Write-Host ""
Write-Host "  Release : $Tarball"
Write-Host "  Size    : $sizeStr"
Write-Host "  SHA256  : $hash"
Write-Host ""
Write-Host "Next step -- deploy to the Raspberry Pi:"
Write-Host "  scp `"$Tarball`" pi@rud1.local:/tmp/"
Write-Host "  ssh pi@rud1.local `"sudo rm -rf /tmp/rud1-release && mkdir -p /tmp/rud1-release && tar -C /tmp/rud1-release -xzf /tmp/$base && sudo bash /tmp/rud1-release/install.sh`""
Write-Host ""
