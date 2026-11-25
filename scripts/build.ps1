<#
.SYNOPSIS
  Builds RDP Monitor: runs the tests, builds release binaries and the MSI.

.EXAMPLE
  .\scripts\build.ps1
  .\scripts\build.ps1 -Release -ReleaseKey C:\keys\release.key -CertThumbprint 0123ABCD...

.PARAMETER Release
  A build for deployment: fails unless both -ReleaseKey and -CertThumbprint
  are given. Without -Release, a build missing either is a development build:
  the MSI is named *-unsigned.msi and a warning is printed.

.PARAMETER ReleaseKey
  Optional rdpmon-tool private key. When given, writes dist\<msi>.sig for
  in-app updates (keep the key offline; run this on a secured build machine).
.PARAMETER CertThumbprint
  Optional code-signing certificate (CurrentUser\My or LocalMachine\My) used
  to Authenticode-sign the executables and the MSI with signtool.exe.
#>
param(
    [switch]$Release,
    [switch]$SkipTests,
    [string]$ReleaseKey,
    [string]$CertThumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)
# Native tools (cargo, wix) write progress to stderr; failures are detected
# through $LASTEXITCODE below, so stderr must not be treated as an error.
$ErrorActionPreference = "Continue"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $version = ([regex]'(?m)^version\s*=\s*"([^"]+)"').Match((Get-Content Cargo.toml -Raw)).Groups[1].Value
    if (-not $version) { throw "cannot read version from Cargo.toml" }
    Write-Host "== RDP Monitor $version"

    $signed = [bool]$CertThumbprint -and [bool]$ReleaseKey
    if ($Release -and -not $signed) {
        Write-Host "ERROR: -Release needs both -CertThumbprint (Authenticode) and -ReleaseKey (update signature)." -ForegroundColor Red
        exit 1
    }

    if (-not $SkipTests) {
        cargo test --workspace
        if ($LASTEXITCODE) { throw "tests failed" }
    }

    cargo build --release -p rdpmon-svc -p rdpmon-config -p rdpmon-tool
    if ($LASTEXITCODE) { throw "cargo build failed" }
    $bin = Join-Path $root "target\release"

    function Invoke-Sign([string]$file) {
        if (-not $CertThumbprint) { return }
        $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)" }
        & $signtool.FullName sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $file
        if ($LASTEXITCODE) { throw "signtool failed for $file" }
    }
    Invoke-Sign "$bin\rdpmon-svc.exe"
    Invoke-Sign "$bin\rdpmon-config.exe"

    $dist = Join-Path $root "dist"
    New-Item -ItemType Directory -Force $dist | Out-Null
    # The update client only accepts RDPMonitor-<version>-x64.msi (with .sig),
    # so an unsigned build can never be served as an update by mistake.
    $suffix = if ($signed) { "" } else { "-unsigned" }
    $msi = Join-Path $dist "RDPMonitor-$version-x64$suffix.msi"

    Push-Location installer
    try {
        dotnet tool restore | Out-Null
        if ($LASTEXITCODE) { throw "dotnet tool restore failed" }
        $installerDir = (Get-Location).Path
        dotnet wix build RDPMonitor.wxs -arch x64 `
            -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext `
            -d "Version=$version" -d "BinDir=$bin" -d "DocDir=$root" -d "InstallerDir=$installerDir" `
            -o $msi
        if ($LASTEXITCODE) { throw "wix build failed" }
    } finally { Pop-Location }
    Remove-Item (Join-Path $dist "*.wixpdb") -ErrorAction SilentlyContinue
    Invoke-Sign $msi

    if ($ReleaseKey) {
        & "$bin\rdpmon-tool.exe" sign-release --key $ReleaseKey --file $msi --version $version
        if ($LASTEXITCODE) { throw "release signing failed" }
    }
    Copy-Item "$bin\rdpmon-tool.exe" $dist -Force
    Write-Host "== Built $msi"
    Get-ChildItem $dist | Format-Table Name, Length
    if (-not $signed) {
        $missing = @()
        if (-not $CertThumbprint) { $missing += "no Authenticode signature (-CertThumbprint)" }
        if (-not $ReleaseKey) { $missing += "no update signature (-ReleaseKey)" }
        Write-Host ""
        Write-Host "UNSIGNED BUILD - not for deployment ($($missing -join ', '))." -ForegroundColor Yellow
        Write-Host "Use -Release with both signing options for a deployable build." -ForegroundColor Yellow
    }
} finally { Pop-Location }
