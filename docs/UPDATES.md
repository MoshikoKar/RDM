# Application updates

Application updates change program files only. Configuration changes are a
separate operation ([DEPLOYMENT.md](DEPLOYMENT.md#4-changing-settings-on-installed-agents));
an update never downloads or applies configuration.

## Publishing a release

1. Set the new version in `Cargo.toml` (`[workspace.package] version`, semantic
   versioning, e.g. `0.2.2`) and commit it to `main`.
2. Tag and push:

   ```powershell
   git tag v0.2.2
   git push origin v0.2.2
   ```

That's all. The **Release** workflow (`.github/workflows/release.yml`) checks
that the tag matches `Cargo.toml`, runs the tests, builds the MSI, signs it with
the `RELEASE_KEY` repository secret, checks the signature against the key built
into the agents, and publishes the GitHub Release with
`RDPMonitor-<version>-x64.msi` and `RDPMonitor-<version>-x64.msi.sig`. Agents
install it at their next daily check.

One-time setup: the private key lives in the repository secret `RELEASE_KEY`
(Settings > Secrets and variables > Actions). Its public half is
`BUILTIN_UPDATE_SIGNING_KEY` in `crates/rdpmon-core/src/config.rs`. Keep an
offline backup of the private key. Replacing it means shipping one release
signed with the old key that contains the new built-in public key.

A local build can still be signed by hand:
`.\scripts\build.ps1 -Release -ReleaseKey <path>\release.key [-CertThumbprint <cert>]`.
A build without the release key is named `*-unsigned.msi`, and agents never
install it.

Drafts and pre-releases (GitHub *pre-release* flag, GitLab upcoming releases,
or a semver pre-release tag like `1.2.0-rc.1`) are ignored unless
`allow_prerelease = true`. Releases without both assets are ignored.

## Configuring agents

Nothing needs to be configured. By default every agent uses the official
repository and the built-in signing key, checks once a day at 03:00 local time,
and installs a newer release by itself. To change this, use the configuration
utility (**Updates**) or a package:

```toml
[updates]
provider = "github"                       # "none" disables updates; or "gitlab"
repository_url = "https://github.com/MoshikoKar/RDM"
token = ""                                # private repositories only, read-only
signing_public_key = ""                   # empty = built-in key; set only for your own release key
auto_install = true                       # false = check/install only from the utility
check_time = "03:00"
```

Agents upgraded from 0.2.0 or older that never had an update source set up
get these defaults automatically. A source that was set up explicitly is kept.

GitHub Enterprise Server URLs (`https://ghe.example.com/owner/repo`) use
`/api/v3` automatically. Self-hosted GitLab works with any host name and port.

## Installing from the configuration utility

Every day at `check_time` (and right after the service starts, if that day's
check was missed) the agent asks the repository for the newest eligible
version. With `auto_install` it installs it right away. **Updates > Check for
updates** does the same on demand and shows the release notes. Installing
(automatic or **Download and install**):

1. Re-reads the release list and confirms the version is newer than the
   installed one (no downgrades).
2. Downloads the `.sig` and the MSI into `C:\ProgramData\RDP Monitor\updates`
   (SYSTEM-only write access), hashing while downloading.
3. Verifies the signature with the update signing key for that exact file name,
   version and SHA-256. Anything else is deleted and rejected.
4. Starts `msiexec /i <msi> /qn /norestart /l*v updates\install-<version>.log`.
   Running copies of the configuration utility are closed first. Windows
   Installer stops the service, replaces the files and starts the new
   version (normally within a minute or two). Monitoring resumes from the
   event-log bookmarks, so no connection is lost.
5. The new service records *update installed* (or *update not installed*, with
   the log path) in the audit log.

## Trust model

- Trust comes only from the Ed25519 signature. Replaced release files, a stolen
  read token or TLS interception cannot produce an MSI the agent accepts without
  the release key. The key is stored as a GitHub Actions secret, so anyone who
  can change the repository's workflows can still get a release signed. Protect
  the GitHub account (2FA) and limit who has write access.
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
