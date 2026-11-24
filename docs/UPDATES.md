# Application updates

Application updates change program files only. Configuration changes are a
separate operation ([DEPLOYMENT.md](DEPLOYMENT.md#4-changing-settings-on-installed-agents));
an update never downloads or applies configuration.

## Publishing a release

1. Set the new version in `Cargo.toml` (`[workspace.package] version`, semantic
   versioning, e.g. `1.1.0`).
2. Build and sign on a secured build machine:

   ```powershell
   .\scripts\build.ps1 -ReleaseKey D:\keys\release.key [-CertThumbprint <code-signing cert>]
   ```

   This produces `dist\RDPMonitor-1.1.0-x64.msi` and `dist\RDPMonitor-1.1.0-x64.msi.sig`.
   Check it: `rdpmon-tool verify-release --pub release.pub --file dist\RDPMonitor-1.1.0-x64.msi --version 1.1.0`
3. Publish a release whose tag is the version (`v1.1.0` or `1.1.0`) with **both
   files attached under exactly these names**.

   GitHub:
   ```powershell
   gh release create v1.1.0 dist\RDPMonitor-1.1.0-x64.msi dist\RDPMonitor-1.1.0-x64.msi.sig --notes-file notes.md
   ```

   GitLab (generic package registry + release links), with `$P` = project ID and a token with `api` scope:
   ```powershell
   $h = @{ "PRIVATE-TOKEN" = $env:GITLAB_TOKEN }
   $base = "https://gitlab.example.com/api/v4/projects/$P"
   foreach ($f in "RDPMonitor-1.1.0-x64.msi", "RDPMonitor-1.1.0-x64.msi.sig") {
     Invoke-RestMethod -Method Put -Headers $h -InFile "dist\$f" -Uri "$base/packages/generic/rdp-monitor/1.1.0/$f"
   }
   $links = "RDPMonitor-1.1.0-x64.msi", "RDPMonitor-1.1.0-x64.msi.sig" | ForEach-Object {
     @{ name = $_; url = "$base/packages/generic/rdp-monitor/1.1.0/$_"; link_type = "package" } }
   $body = @{ tag_name = "v1.1.0"; ref = "main"; description = (Get-Content notes.md -Raw); assets = @{ links = $links } } | ConvertTo-Json -Depth 5
   Invoke-RestMethod -Method Post -Headers $h -ContentType "application/json" -Body $body -Uri "$base/releases"
   ```
   Asset links must point to the same GitLab server; links to other hosts are ignored.

Drafts and pre-releases (GitHub *pre-release* flag, GitLab upcoming releases,
or a semver pre-release tag like `1.2.0-rc.1`) are ignored unless
`allow_prerelease = true`. Releases without both assets are ignored.

## Configuring agents

In the configuration utility (**Updates**) or in a package:

```toml
[updates]
provider = "github"                       # or "gitlab"
repository_url = "https://github.com/acme/rdp-monitor"   # GitLab: https://gitlab.example.com/group/project
token = ""                                # private repositories only, read-only
signing_public_key = "<contents of release.pub>"
```

GitHub Enterprise Server URLs (`https://ghe.example.com/owner/repo`) use
`/api/v3` automatically. Self-hosted GitLab works with any host name and port.

## Installing from the configuration utility

**Updates > Check for updates** contacts the configured repository (never
automatically), lists the newest eligible version and its release notes.
**Download and install**:

1. Re-reads the release list and confirms the version is newer than the
   installed one (no downgrades).
2. Downloads the `.sig` and the MSI into `C:\ProgramData\RDP Monitor\updates`
   (SYSTEM-only write access), hashing while downloading.
3. Verifies the signature with `signing_public_key` for that exact file name,
   version and SHA-256. Anything else is deleted and rejected.
4. Starts `msiexec /i <msi> /qn /norestart /l*v updates\install-<version>.log`.
   Windows Installer stops the service, replaces the files and starts the new
   version (normally within a minute or two). Monitoring resumes from the
   event-log bookmarks, so no connection is lost.
5. The new service records *update installed* (or *update not installed*, with
   the log path) in the audit log.

## Trust model

- Trust comes only from the offline Ed25519 signature. A compromised repository,
  stolen repository token or TLS interception cannot produce an MSI the agent
  accepts without `release.key`.
- The signature covers the file name, version and hash, so a valid signature
  for an old version cannot be presented as a newer one.
- Authenticode-signing the MSI (`-CertThumbprint`) is recommended in addition,
  for Windows SmartScreen and for deployments outside the in-app updater.
- TLS uses Windows certificate validation (WinHTTP/SChannel) and the system
  proxy settings. Redirects: HTTPS only, at most 5, token stripped when the host
  changes.

## Rollback and failures

- The MSI uses a major upgrade scheduled inside the installation transaction:
  if the new version fails to install, Windows Installer restores the previous
  version.
- Data in `C:\ProgramData\RDP Monitor` is never removed by an upgrade. Before
  any future database schema migration the service copies `history.db` to
  `history.db.bak-v<old schema>`. Schema migrations are forward-only: after a
  successful upgrade, reinstalling an older version is refused by the MSI, and an
  older service refuses to open a newer database rather than corrupt it.

## Enterprise upgrades

GPO, Vicarius and manual installation use the same MSI; see
[DEPLOYMENT.md](DEPLOYMENT.md#7-upgrades). All paths preserve configuration,
credentials, password, history and queued notifications.
