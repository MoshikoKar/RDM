# Changelog

## 0.2.2 - 2026-11-25

No functional changes. This release exercises the automatic update path
(0.2.1 to 0.2.2).

## 0.2.1 - 2026-11-25

### Added
- **Automatic updates.** Agents check the official GitHub repository once a day
  (03:00 by default) and install newer signed releases themselves. Settings and
  history are kept. Use the Updates page to turn this off or change the time.
- Releases are built, signed and published by GitHub Actions when a `v*` tag is
  pushed.

### Changed
- No update configuration is needed: the official repository and its signing
  key are built in. Agents that never had an update source set up switch to it
  automatically.
- Upgrades close a running configuration utility first, so files are never left
  waiting for a reboot.
- **Check for updates** asks you to save changed update settings first, instead
  of reporting an invalid repository URL.

## 0.2.0 - 2026-11-25

Every new alert type is **off by default**. With an unchanged configuration,
0.2.0 sends the same emails as 0.1.1, plus the new informational rows in RDP
alerts. The history database is upgraded automatically (schema v3). A backup of
the old file is kept as `history.db.bak-v1`.

### Added
- **Source hostname** row in RDP alerts. The agent looks up the source IP's name
  (DNS PTR, hosts file, NetBIOS/LLMNR), only for emails actually sent, and gives
  up after 3 s.
- **Failed logons** (`[failed_logons]`, #1): Security 4625 (LogonType 3 and 10).
  Attempts are counted per source IP, with one email when a threshold is reached
  (default 5 in 5 min). The email shows the accounts tried, readable reasons,
  and first/last time. All attempts are kept in history and counted in the
  weekly report.
- **Shared folder (SMB) access** (`[smb]`, #9):
  - Covers access (5140), access denied (5145, failure only, filtered in the
    event log service), and wrong passwords (4625 type 3).
  - `exclude_shares` and `admin_shares_only` stop the email but still record the
    event in history.
  - The weekly report has a share section.
  - The agent warns in its status when a required audit subcategory is off.
- **Client workstation (reported)** row from 4624 WorkstationName and
  4778/4779 ClientName (#3). It is display-only, because the client chooses it.
- **Context rows** in RDP alerts (#4):
  - Source network: Internal or External, plus `internal_networks`.
  - First seen: first connection by this user, from this IP, or of this pair.
  - Outside business hours: only when `business_hours` is set.
- **Disconnect and logoff emails** (`notify_disconnects`, `notify_logoffs`, #5),
  with session start, end and duration, and their own quiet period.
- **Daily heartbeat** and an **email-outage recovery summary** (`[heartbeat]`, #2).
  The heartbeat subject says OK or WARNING. The summary reports how many alerts
  were delayed, dropped or given up.
- **CI** on windows-latest: tests plus an unsigned MSI artifact (#8).

### Fixed
- Correlation and cooldown keys include the normalized account domain, so
  `CORP\admin` and the local `PC01\admin` are no longer merged or suppressed
  together (#6).
- One RDP session whose events report different addresses (RD Gateway / NAT,
  IPv4 and IPv6) is no longer split into two alerts. The 4624 address is the
  Source IP, and the others are shown as "Other addresses seen" (#7).

### Changed
- `scripts/build.ps1 -Release` refuses to build without both the code-signing
  certificate and the update signing key. Builds without them are named
  `*-unsigned.msi` and end with an `UNSIGNED BUILD` warning (#8).
- Event subscriptions are re-created whenever a setting changes which events are
  selected, not only for `[monitoring]` changes.
