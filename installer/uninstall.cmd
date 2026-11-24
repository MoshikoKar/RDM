@echo off
:: Start menu "Uninstall RDP Monitor": requests elevation, prompts for the RDP
:: Monitor administration password, stops the service and removes the product.
:: The script runs from a copy in %TEMP%, so nothing in the installation folder
:: is in use while msiexec removes it. Each command line below is parsed whole
:: before it runs, so cmd never needs to re-read this file after it is deleted.
fltmc >nul 2>&1 || (powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
copy /y "%~dp0Uninstall-RDPMonitor.ps1" "%TEMP%\RDPMonitor-Uninstall.ps1" >nul & cd /d "%TEMP%" & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\RDPMonitor-Uninstall.ps1" & pause & del "%TEMP%\RDPMonitor-Uninstall.ps1" >nul 2>&1 & exit /b
