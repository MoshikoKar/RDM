<#
.SYNOPSIS
  Silent, authorized removal of RDP Monitor for GPO / Vicarius (runs as SYSTEM).

.DESCRIPTION
  Removal is blocked unless authorized. For deployment tools the authorization
  is a signed configuration package whose [package] section contains
  `authorize_uninstall = true` and a serial higher than any package applied
  before (so an old package cannot be replayed). This script imports that
  package, then runs msiexec /x. Data in C:\ProgramData\RDP Monitor is kept.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-RDPMonitor.ps1 `
    -AuthorizationPackage \\fs01\deploy$\rdpmon\remove-2026120101.rdpcfg
#>
param(
    [Parameter(Mandatory = $true)][string]$AuthorizationPackage,
    [string]$LogDir = "$env:WINDIR\Temp"
)
$ErrorActionPreference = "Continue"
$app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "RDP Monitor" } | Select-Object -First 1
if (-not $app) { Write-Output "RDP Monitor is not installed."; exit 0 }

$svc = Join-Path $env:ProgramFiles "RDP Monitor\rdpmon-svc.exe"
& $svc import $AuthorizationPackage
if ($LASTEXITCODE -ne 0) { Write-Error "Authorization package rejected (exit $LASTEXITCODE)."; exit $LASTEXITCODE }

$code = $app.PSChildName   # product code {GUID}
$log = Join-Path $LogDir "RDPMonitor-uninstall.log"
$p = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -ArgumentList @("/x", $code, "/qn", "/norestart", "/l*v", "`"$log`"") -Wait -PassThru
Write-Output "msiexec exit code $($p.ExitCode); log: $log"
exit $p.ExitCode
