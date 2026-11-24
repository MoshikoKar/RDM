<#
.SYNOPSIS
  Creates an MSI transform (.mst) that presets TRUSTED_CONFIG_KEY and
  CONFIG_PACKAGE, for Group Policy Software Installation (which cannot pass
  msiexec command-line properties). Create one transform per configuration
  group (site, department, server role).

.EXAMPLE
  .\New-RDPMonitorTransform.ps1 -MsiPath .\RDPMonitor-0.1.1-x64.msi `
     -TrustedConfigKey (Get-Content .\cfg.pub) `
     -ConfigPackage "\\fs01\deploy$\rdpmon\site-a.rdpcfg" -OutFile .\site-a.mst
#>
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [Parameter(Mandatory = $true)][string]$TrustedConfigKey,
    [string]$ConfigPackage = "",
    [Parameter(Mandatory = $true)][string]$OutFile
)
$ErrorActionPreference = "Stop"

function Invoke-Com($obj, [string]$name, [string]$kind, [object[]]$params) {
    $flags = [System.Reflection.BindingFlags]::$kind
    $obj.GetType().InvokeMember($name, $flags, $null, $obj, $params)
}

$msi = (Resolve-Path $MsiPath).Path
$OutFile = [System.IO.Path]::GetFullPath($OutFile)
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpmon-mst-" + [guid]::NewGuid() + ".msi")
Copy-Item $msi $work
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = Invoke-Com $installer "OpenDatabase" "InvokeMethod" @([string]$work, [int]1)
    $props = @{ "TRUSTED_CONFIG_KEY" = $TrustedConfigKey.Trim() }
    if ($ConfigPackage) { $props["CONFIG_PACKAGE"] = $ConfigPackage }
    foreach ($k in $props.Keys) {
        $del = Invoke-Com $db "OpenView" "InvokeMethod" @("DELETE FROM Property WHERE Property='$k'")
        Invoke-Com $del "Execute" "InvokeMethod" $null | Out-Null
        Invoke-Com $del "Close" "InvokeMethod" $null | Out-Null
        $ins = Invoke-Com $db "OpenView" "InvokeMethod" @("INSERT INTO Property (Property, Value) VALUES (?, ?)")
        $rec = Invoke-Com $installer "CreateRecord" "InvokeMethod" @([int]2)
        Invoke-Com $rec "StringData" "SetProperty" @([int]1, [string]$k) | Out-Null
        Invoke-Com $rec "StringData" "SetProperty" @([int]2, [string]$props[$k]) | Out-Null
        Invoke-Com $ins "Execute" "InvokeMethod" @($rec) | Out-Null
        Invoke-Com $ins "Close" "InvokeMethod" $null | Out-Null
    }
    Invoke-Com $db "Commit" "InvokeMethod" $null | Out-Null
    $orig = Invoke-Com $installer "OpenDatabase" "InvokeMethod" @([string]$msi, [int]0)
    Invoke-Com $db "GenerateTransform" "InvokeMethod" @($orig, [string]$OutFile) | Out-Null
    Invoke-Com $db "CreateTransformSummaryInfo" "InvokeMethod" @($orig, [string]$OutFile, [int]0, [int]0) | Out-Null
    Write-Output "Transform written to $OutFile"
} finally {
    $db = $null; $orig = $null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    Remove-Item $work -ErrorAction SilentlyContinue
}
