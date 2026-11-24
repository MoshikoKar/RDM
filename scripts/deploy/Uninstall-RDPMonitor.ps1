<#
.SYNOPSIS
  Remove RDP Monitor after authorization (interactive password or signed package).

.DESCRIPTION
  Removal is blocked unless authorized. Choose one:

  Interactive: prompts for the RDP Monitor administration password, opens the
  10-minute removal window, then runs msiexec (the MSI stops the RDPMonitor
  service and removes the product).

  Enterprise / GPO / Vicarius: pass -AuthorizationPackage pointing at a signed
  .rdpcfg whose [package] section has authorize_uninstall = true and a serial
  higher than any package applied before.

  Data in C:\ProgramData\RDP Monitor is kept.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-RDPMonitor.ps1

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-RDPMonitor.ps1 `
    -AuthorizationPackage \\fs01\deploy$\rdpmon\remove-2026120101.rdpcfg
#>
param(
    [string]$AuthorizationPackage,
    [string]$LogDir = "$env:WINDIR\Temp"
)
$ErrorActionPreference = "Continue"
$app = Get-ItemProperty @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
) -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "RDP Monitor" } | Select-Object -First 1
if (-not $app) { Write-Output "RDP Monitor is not installed."; exit 0 }

$svc = Join-Path $env:ProgramFiles "RDP Monitor\rdpmon-svc.exe"
if (-not (Test-Path $svc)) {
    Write-Error "rdpmon-svc.exe not found at $svc"
    exit 6
}

if ($AuthorizationPackage) {
    & $svc import $AuthorizationPackage
    if ($LASTEXITCODE -ne 0) { Write-Error "Authorization package rejected (exit $LASTEXITCODE)."; exit $LASTEXITCODE }
} else {
    Write-Host "Enter the RDP Monitor administration password to stop the service and uninstall."
    & $svc authorize-uninstall
    if ($LASTEXITCODE -ne 0) { Write-Error "Authorization failed (exit $LASTEXITCODE)."; exit $LASTEXITCODE }
}

$code = $app.PSChildName
$log = Join-Path $LogDir "RDPMonitor-uninstall.log"
Write-Host "Stopping RDP Monitor and removing the product..."
Set-Location $env:TEMP   # never hold the installation folder open during removal
$p = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -ArgumentList @("/x", $code, "/qb", "/norestart", "/l*v", "`"$log`"") -Wait -PassThru
Write-Output "msiexec exit code $($p.ExitCode); log: $log"
exit $p.ExitCode
