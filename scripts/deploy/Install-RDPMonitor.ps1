<#
.SYNOPSIS
  Idempotent install / upgrade / reconfigure of RDP Monitor for GPO computer
  startup scripts, Vicarius (vRx) scripts and other tools that run as SYSTEM.

.DESCRIPTION
  1. If RDP Monitor is missing or older than the MSI: installs/upgrades it silently.
  2. Otherwise, if -ConfigPackage is given: applies it with `rdpmon-svc import`
     (a package that is already applied is a successful no-op; an older one is rejected).
  Safe to run at every boot. Never pass passwords to this script: secrets travel
  only inside signed configuration packages.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-RDPMonitor.ps1 `
    -MsiPath \\fs01\deploy$\rdpmon\RDPMonitor-1.0.0-x64.msi `
    -TrustedConfigKey "2hmFowmQBPgKUEK72t3e+ln4S1d6O6OSfURdnr2kn/A=" `
    -ConfigPackage \\fs01\deploy$\rdpmon\site-a.rdpcfg

.NOTES
  Exit codes: 0 success, 3010 success (restart required),
  msiexec codes (e.g. 1603) when installation fails,
  rdpmon-svc import codes 2-6 when the configuration package fails.
#>
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [string]$TrustedConfigKey = "",
    [string]$ConfigPackage = "",
    [string]$LogDir = "$env:WINDIR\Temp"
)
$ErrorActionPreference = "Continue"

function Get-MsiVersion([string]$path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($path, 0))
    $view = $db.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $db, @("SELECT Value FROM Property WHERE Property='ProductVersion'"))
    $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
    $rec = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
    $v = $rec.GetType().InvokeMember("StringData", "GetProperty", $null, $rec, [object[]]@([int]1))
    $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null) | Out-Null
    [version]$v
}

function Get-InstalledVersion {
    $keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $app = Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "RDP Monitor" } | Select-Object -First 1
    if ($app -and $app.DisplayVersion) { [version]$app.DisplayVersion } else { $null }
}

if (-not (Test-Path $MsiPath)) { Write-Error "MSI not found: $MsiPath"; exit 2 }
$msiVersion = Get-MsiVersion $MsiPath
$installed = Get-InstalledVersion
$svc = Join-Path $env:ProgramFiles "RDP Monitor\rdpmon-svc.exe"

if (-not $installed -or $installed -lt $msiVersion) {
    $log = Join-Path $LogDir "RDPMonitor-$msiVersion-install.log"
    $msiArgs = @("/i", "`"$MsiPath`"", "/qn", "/norestart", "/l*v", "`"$log`"")
    if ($TrustedConfigKey) { $msiArgs += "TRUSTED_CONFIG_KEY=`"$TrustedConfigKey`"" }
    if ($ConfigPackage) { $msiArgs += "CONFIG_PACKAGE=`"$ConfigPackage`"" }
    Write-Output "Installing RDP Monitor $msiVersion (installed: $(if ($installed) { $installed } else { 'none' }))"
    $p = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    Write-Output "msiexec exit code $($p.ExitCode); log: $log"
    exit $p.ExitCode
}

if ($ConfigPackage) {
    & $svc import $ConfigPackage
    exit $LASTEXITCODE
}
Write-Output "RDP Monitor $installed is installed and up to date."
exit 0
