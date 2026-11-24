@echo off
:: Elevated uninstaller: prompts for the RDP Monitor administration password,
:: stops the service, and removes the product.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-RDPMonitor.ps1"
if errorlevel 1 pause
