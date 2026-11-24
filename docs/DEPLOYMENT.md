# Deployment guide

For IT administrators deploying RDP Monitor silently (msiexec, Group Policy,
Vicarius vRx or another MSI deployment tool) and managing its configuration
afterwards.

- [1. One-time preparation: keys](#1-one-time-preparation-keys)
- [2. Configuration packages](#2-configuration-packages)
- [3. Silent installation](#3-silent-installation)
- [4. Changing settings on installed agents](#4-changing-settings-on-installed-agents)
- [5. Group Policy (GPO)](#5-group-policy-gpo)
- [6. Vicarius vRx](#6-vicarius-vrx)
- [7. Upgrades](#7-upgrades)
- [8. Removal](#8-removal)
- [Exit codes](#exit-codes)

## 1. One-time preparation: keys

Run `rdpmon-tool.exe` (in `dist\`, never installed on endpoints) on an
administrator workstation:

```powershell
rdpmon-tool keygen cfg       # cfg.key (private) + cfg.pub  - signs configuration packages
rdpmon-tool keygen release   # release.key + release.pub    - signs application updates
```

- Keep `*.key` files offline or in a protected vault. Whoever holds `cfg.key`
  can reconfigure every agent that trusts `cfg.pub`.
- `cfg.pub` is installed on endpoints at first installation (`TRUSTED_CONFIG_KEY`).
  It is a public key, safe to put on a command line or in a transform.
- `release.pub` goes into `[updates] signing_public_key`.
- To rotate the configuration key later, sign a package with the *current* key
  containing `[package] new_trusted_config_key = "<new public key>"`.

## 2. Configuration packages

A package is a TOML payload (any subset of the settings in
[examples/config.example.toml](../examples/config.example.toml)) with a
`[package]` header, signed with `cfg.key`:

```powershell
rdpmon-tool hash-password            # prompts; prints $argon2id$... for admin_password_hash
rdpmon-tool sign-config --key cfg.key --in site-a.toml --out site-a.rdpcfg
rdpmon-tool verify-config --pub cfg.pub --in site-a.rdpcfg
```

Rules enforced by the agent:

| Rule | Effect |
|---|---|
| Signature must verify with the computer's trusted key | otherwise rejected (exit code 4) |
| `serial` must be higher than the last applied package | older packages rejected; the same package again = success, no change |
| Only keys present are changed; lists replace the old list | a package with only `[smtp] to = [...]` changes only the recipients |
| The result must pass full validation | invalid settings rejected (exit code 5), nothing changed |
| `security.trusted_config_key` / `last_package_serial` cannot be set | use `[package] new_trusted_config_key` |
| Never modifies history, queued emails or the installed version | configuration and application updates are separate |

**Different settings per group of computers:** create one payload and one
signed package per group (site, department, server role), each in its own share
folder or with its own file name, and target them with separate GPOs / Vicarius
groups. Serials only need to increase *per computer*; using `YYYYMMDDnn` for all
packages keeps it simple.

Examples: [examples/package-site-a.toml](../examples/package-site-a.toml),
[examples/package-smtp-auth.toml](../examples/package-smtp-auth.toml).

### Secrets in packages

Packages are **signed, not encrypted**. An SMTP password or update token in a
package can be read by anyone who can read the `.rdpcfg` file, and every
computer receiving the package receives the same secret. Encrypting the file
with a key that every endpoint can use would not change that. Recommended, in
order of preference:

1. Use an SMTP relay that accepts mail from your internal networks **without
   authentication** (the setup used by the original PowerShell scripts); the
   package then contains no secret at all.
2. Otherwise create a dedicated send-only mailbox **per group**, restricted to
   sending to your alert addresses, and rotate its password periodically.
3. Restrict the share: `Domain Computers` (or the target computers' group) read,
   administrators full, no access for users. Remove the package from the share
   after the rollout if your deployment tool copies it locally.
4. Never put the *administration password* in a package - only its Argon2id hash
   (`rdpmon-tool hash-password`).

Once applied, the agent stores secrets encrypted with DPAPI for the SYSTEM
account and never displays them again.

## 3. Silent installation

```powershell
# Plain install (no email yet; an administrator finishes setup in the UI)
msiexec /i RDPMonitor-1.0.0-x64.msi /qn /norestart /l*v C:\Windows\Temp\rdpmon-install.log

# Preconfigured install
msiexec /i RDPMonitor-1.0.0-x64.msi /qn /norestart /l*v C:\Windows\Temp\rdpmon-install.log ^
  TRUSTED_CONFIG_KEY="2hmFowmQBPgKUEK72t3e+ln4S1d6O6OSfURdnr2kn/A=" ^
  CONFIG_PACKAGE="\\fs01\deploy$\rdpmon\site-a.rdpcfg"
```

| Property | Meaning |
|---|---|
| `TRUSTED_CONFIG_KEY` | Public key trusted for packages. Honoured only on a never-configured agent (first installation, before an administration password exists). On an agent that was set up interactively, enter the key in the configuration utility (Security). An installed key can be changed only by a package signed with it. |
| `CONFIG_PACKAGE` | Signed package applied during installation (local path or UNC path readable by the computer account). |

There are deliberately no properties for SMTP passwords or the administration
password: they would appear in process lists and could leak into logs.

What the MSI does: installs to `C:\Program Files\RDP Monitor`, registers the
`RDPMonitor` service (LocalSystem, automatic start, restart on failure), runs
`rdpmon-svc provision` as SYSTEM to validate and apply the package **before** the
service starts, starts the service. If the package is invalid the installation
fails and rolls back (exit code 1603); the reason is in the MSI log (search for
`rdpmon-svc` / `WixQuietExec`) and in `C:\ProgramData\RDP Monitor\logs\service.log`.

If no package sets `admin_password_hash`, the first person to open the
configuration utility as Administrator sets the password - include the hash in
the package for unattended deployments.

## 4. Changing settings on installed agents

No reinstallation is needed. Run as SYSTEM or an elevated Administrator:

```powershell
& "C:\Program Files\RDP Monitor\rdpmon-svc.exe" import "\\fs01\deploy$\rdpmon\site-a-2026120101.rdpcfg"
```

The running service verifies the signature, checks the serial, validates and
applies the settings immediately (no restart, monitoring continues), and records
the change in the audit log. Typical changes: SMTP host or credentials,
recipients, cooldown, reconnection notifications, weekly report day/time,
administration password hash.

Local Administrators cannot use `import` to change settings without a package
signed by your key, and cannot re-apply an older package.

## 5. Group Policy (GPO)

### Option A - Software Installation (MSI) with a transform

GPO Software Installation cannot pass msiexec properties, so create a transform
per configuration group:

```powershell
.\scripts\deploy\New-RDPMonitorTransform.ps1 -MsiPath .\RDPMonitor-1.0.0-x64.msi `
  -TrustedConfigKey (Get-Content .\cfg.pub) `
  -ConfigPackage "\\fs01\deploy$\rdpmon\site-a.rdpcfg" -OutFile .\site-a.mst
```

1. Copy the MSI, the `.mst` and the `.rdpcfg` to a share readable by
   `Domain Computers` (e.g. `\\fs01\deploy$\rdpmon`).
2. Group Policy Management > create/edit a GPO linked to the target OU >
   *Computer Configuration > Policies > Software Settings > Software installation*
   > New > Package > select the MSI by its **UNC path** > **Advanced** >
   *Modifications* tab > add `site-a.mst` > OK.
3. Computers install at the next restart.

### Option B - Computer startup script (install, upgrade and reconfigure)

*Computer Configuration > Policies > Windows Settings > Scripts > Startup >
PowerShell Scripts*: add `Install-RDPMonitor.ps1` from `scripts\deploy` with
parameters:

```
-MsiPath \\fs01\deploy$\rdpmon\RDPMonitor-1.0.0-x64.msi -TrustedConfigKey 2hmFowmQ...= -ConfigPackage \\fs01\deploy$\rdpmon\site-a.rdpcfg
```

At every startup it installs or upgrades when the MSI on the share is newer,
otherwise applies the package (already-applied packages are a no-op). To change
settings later, replace `site-a.rdpcfg` with a new package with a higher serial.

## 6. Vicarius vRx

Use vRx's script execution / automation feature to run PowerShell **as SYSTEM**
on the target endpoint group. Exact menu names depend on your vRx version; the
commands are the same.

- **Install / upgrade / reconfigure** - run `Install-RDPMonitor.ps1` with the
  parameters shown in option B above (the MSI and package on a share reachable
  by the endpoints, or copied by vRx to a local folder such as
  `C:\Windows\Temp\rdpmon\`). Alternatively, if you deploy the MSI through vRx's
  application deployment, use the command line from section 3.
- **Change settings only** - run
  `& "C:\Program Files\RDP Monitor\rdpmon-svc.exe" import C:\Windows\Temp\rdpmon\site-a-2026120101.rdpcfg`
- **Remove** - see section 8.
- Treat exit code 0 as success, 3010 as success with restart pending, any other
  value as failure (see [Exit codes](#exit-codes)).
- Use one endpoint group and one package per configuration.

## 7. Upgrades

Any of these installs a newer version over the existing one:

```powershell
msiexec /i RDPMonitor-1.1.0-x64.msi /qn /norestart /l*v C:\Windows\Temp\rdpmon-upgrade.log
```

- GPO option A: add the new MSI to the same GPO and on its *Upgrades* tab mark it
  as upgrading the previous package. Option B: replace the MSI path in the
  startup script parameters.
- Vicarius: run `Install-RDPMonitor.ps1` with the new MSI.
- Interactive: **Updates > Check for updates** in the configuration utility (see
  [UPDATES.md](UPDATES.md)).

Configuration, SMTP credentials, recipients, password, history and queued
notifications are kept (they live in `C:\ProgramData\RDP Monitor`, which the MSI
never touches). Downgrades are refused by the MSI. A failed upgrade rolls back to
the previous version. Do not pass `CONFIG_PACKAGE` with an old serial during an
upgrade - it would fail the upgrade; leave the property empty or use a newer
package.

## 8. Removal

Removal must be authorized. The MSI stops the `RDPMonitor` service as part of
uninstall.

- **Interactive (password)**: Start menu > *Uninstall RDP Monitor*, or
  `"C:\Program Files\RDP Monitor\rdpmon-svc.exe" uninstall`, or configuration
  utility > Security > enter the administration password > *Uninstall now*.
  Each option verifies the password, opens the removal window, then runs
  msiexec (service stop + product removal).
- **Interactive (two-step)**: configuration utility > Security >
  *Authorize uninstall only*, then Settings > Apps > RDP Monitor > Uninstall
  within 10 minutes.
- **Silent (GPO / Vicarius)**: sign a package with a new, higher serial:

  ```toml
  [package]
  serial = 2026120101
  description = "Authorize removal"
  authorize_uninstall = true
  ```

  and run `scripts\deploy\Uninstall-RDPMonitor.ps1 -AuthorizationPackage <file>`
  as SYSTEM. It imports the package (opening a 10-minute window) and runs
  `msiexec /x {product code} /qb`. Without `-AuthorizationPackage` the same
  script prompts for the administration password.

An unauthorized removal fails with exit code 1603 and is recorded in the audit
log. Upgrades are never blocked.

### Removing all data

Uninstallation keeps `C:\ProgramData\RDP Monitor` (history, settings, logs) so a
reinstall continues where it stopped. Administrators have read-only access to it;
to delete it:

```powershell
takeown /f "C:\ProgramData\RDP Monitor" /r /d y
icacls "C:\ProgramData\RDP Monitor" /grant Administrators:F /t
Remove-Item -Recurse -Force "C:\ProgramData\RDP Monitor"
```

## Exit codes

**msiexec**: 0 success; 3010 success, restart required; 1602 cancelled by user;
1603 fatal error (includes invalid configuration package and unauthorized
removal - see the log); 1618 another installation in progress (retry later);
1638 another version already installed (downgrade refused).

### Recovering an agent whose configuration was lost

If `config.dat` and its backup become unreadable, the agent keeps monitoring
but refuses sign-in and setup (see [SECURITY.md](SECURITY.md)). Run, as SYSTEM
(GPO startup script, Vicarius script, or an MSI custom action context):

```powershell
& "C:\Program Files\RDP Monitor\rdpmon-svc.exe" reset
```

then complete the setup wizard, or reinstall/repair with `TRUSTED_CONFIG_KEY`
and `CONFIG_PACKAGE`. The reset is recorded in the audit log.

**rdpmon-svc** (`import`, `provision`, `uninstall-check`, `status`, `reset`):

| Code | Meaning |
|---|---|
| 0 | Success (including "package already applied") |
| 1 | Not authorized (uninstall-check) |
| 2 | Invalid arguments |
| 3 | No trusted configuration key installed |
| 4 | Package rejected: bad signature, wrong key, or older serial |
| 5 | Package settings invalid |
| 6 | Service not running / cannot be reached, or file I/O error |
