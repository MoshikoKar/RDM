# RDP Monitor

A small Windows service that detects Remote Desktop (RDP) connections in real time
and sends email notifications and a weekly report. It replaces the
`rdp-monitor.ps1` / `rdp-weekly-report.ps1` scheduled scripts.

- Event-driven: Windows Event Log subscriptions, no polling. Measured idle: 0 ms CPU over 60 s, ~9 MB working set.
- Runs on each computer by itself: no central server, no telemetry, no listening network port.
- Settings are protected by an administration password and stored encrypted (DPAPI).
- Silent MSI deployment (GPO, Vicarius), signed configuration packages, signed in-app updates.

| Component | Location |
|---|---|
| Service `RDPMonitor` (`rdpmon-svc.exe`) and configuration utility (`rdpmon-config.exe`) | `C:\Program Files\RDP Monitor\` |
| Configuration (`config.dat`, encrypted), history and queue (`history.db`), logs | `C:\ProgramData\RDP Monitor\` |
| Signing tool `rdpmon-tool.exe` (administrators only, not installed on endpoints) | `dist\` |

## Install

**Interactive:** run `RDPMonitor-<version>-x64.msi`. On the last page leave
*Open the RDP Monitor setup wizard now* ticked. The wizard asks for the SMTP server,
recipients, monitoring preferences and an administration password, and lets you
send a test email. The service starts automatically and records connections even
before email is configured.

**Silent / GPO / Vicarius:** see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

```powershell
msiexec /i RDPMonitor-0.1.1-x64.msi /qn /norestart /l*v C:\Windows\Temp\rdpmon-install.log `
  TRUSTED_CONFIG_KEY="<base64 public key>" CONFIG_PACKAGE="\\server\share\rdpmon\site-a.rdpcfg"
```

## Configure

Open **RDP Monitor Configuration** from the Start menu (it asks for elevation),
sign in with the administration password, change settings and click **Save**.
The running service validates and applies them immediately; monitoring is not
interrupted.

| Section | Contents |
|---|---|
| General | version, service and monitoring status, queue, recent connections |
| Email | SMTP server, port, encryption (None / STARTTLS / TLS), user, password, sender, recipients, CC/BCC, subject, **Send test email** |
| Monitoring | event sources, new-login / reconnection notifications, quiet period (cooldown), history retention, weekly report day/time |
| Security | change password, service hardening, trusted configuration key, authorize uninstall, administrative action history |
| Updates | GitHub/GitLab source, token, signing key, **Check for updates**, release notes, **Download and install** |

Deployment tools change settings with signed packages:
`"C:\Program Files\RDP Monitor\rdpmon-svc.exe" import site-a.rdpcfg`. An annotated
example of every setting is in [examples/config.example.toml](examples/config.example.toml).

## How it works

The service subscribes to:

| Channel | Events |
|---|---|
| Security | 4624 (LogonType 10 only, filtered by the Event Log service), 4778 reconnect, 4779 disconnect |
| TerminalServices-LocalSessionManager/Operational | 21 logon, 24 disconnect, 25 reconnect |
| TerminalServices-RemoteConnectionManager/Operational | 1149 authentication (evidence only - never a connection by itself) |

Events for the same account and source IP within 30 s are merged into one connection
(new login or reconnection), so one RDP session produces one email
(`CORP\admin` and the local `PC01\admin` are different accounts; `CORP` and
`corp.local` are the same domain). If the events of one session report different
addresses (RD Gateway or NAT in front of the host, IPv4 and IPv6 of one client),
they are still merged unless their session or logon IDs differ; the 4624 address
is then the Source IP and the others are listed as "Other addresses seen". The
alert also shows the name the client reports for itself (4624 WorkstationName /
4778 ClientName) as "Client workstation (reported)"; any client can send any
name, so it is shown for information only and never used for filtering.
Context rows help judge a connection at a glance (they never change whether or
how it is reported): *Source network* (Internal for private, CGNAT, link-local
and ULA ranges plus `internal_networks`, otherwise External), *First seen*
(first connection by this user / from this IP / of this pair, or the last time
seen - limited by `history_days`), and *Outside business hours* when
`business_hours` is set. Only
RDP-specific events are selected (non-RDP logons such as network or service
logons never reach the agent); built-in identities (`NT AUTHORITY`,
`Window Manager`, `Font Driver Host`) and console (`LOCAL`) sessions are ignored.
Loopback connections are reported by default because RDP through a local tunnel
arrives from 127.0.0.1 (configurable). Every connection is stored in history; emails are subject to
the per account+IP quiet period (default 15 min, 0 = every connection). Bookmarks let
the service pick up events that happened while it was stopped.

Undelivered emails are queued in SQLite and retried with exponential backoff
(1 min ... 1 h) for up to 72 h; monitoring never waits for email.

Optional health emails (`[heartbeat]`, off by default): a daily heartbeat at a
set local time (version, uptime, event channel status including audit policy
warnings, connections in the last 24 h, queue) with subject `... OK` or
`... WARNING` when a channel is not active or emails have waited over an hour;
and `recovery_summary`, one email after an SMTP outage saying how long delivery
failed and how many alerts were delayed, dropped (queue full) or given up.

> 4778/4779 need *Audit Other Logon/Logoff Events* (Success). Without it the
> Session Manager events still detect reconnections.
> `auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable`

### Optional alerts (all off by default)

**Disconnections and logoffs** (`notify_disconnects`, `notify_logoffs`): an
email when a session is disconnected (4779 / LSM 24) or the user logs off
(LSM 23, subscribed only when enabled), with session start, end and duration.
The start is the user's latest logon or reconnection with the same session ID
(or from the same IP); "unknown" when there is none, e.g. a session that began
before the agent was installed, or a local console session. These have their own
quiet period and never affect logon alerts.

**Failed logons** (`[failed_logons]`): subscribes to Security 4625 with
LogonType 3 or 10. With NLA (the default) a wrong RDP password is logged as a
*network* (type 3) logon, so the count also includes failed file-share and other
network logons, and the email says "Failed logon", not "RDP". Each attempt is
stored in history; an email is sent when one source IP reaches `threshold`
failures within `window_minutes` (default 5 in 5 min), then at most once per IP
per quiet period (never more often than the window). The weekly report shows the
total. Needs *Audit Logon* failure auditing, which Windows enables by default:
`auditpol /set /subcategory:"Logon" /failure:enable`

**Shared folders (SMB)** (`[smb]`): reports access to this computer's shares,
admin shares (`C$`, `ADMIN$`) and regular ones alike, from other machines.

| Case | Event | Email |
|---|---|---|
| Share opened | 5140 (once per session per share) | "Share access" with user, IP, hostname, share |
| Valid account, no permission | 5145 *failure only* (filtered in the event log service) | "Share access denied" with the path |
| Wrong password | 4625 LogonType 3 | "Failed logon", same threshold as above |

One email per account + IP + share per quiet period. `exclude_shares` (e.g.
`IPC$`, `print$`) and `admin_shares_only` only suppress the email; every event is
still recorded in history, and the weekly report lists share access per user, IP
and share. Account names are not filtered (an account named `x$` still alerts).
Prerequisites - the status page shows a warning when one is missing:

```
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Detailed File Share" /failure:enable   # never /success: one event per file
auditpol /set /subcategory:"Logon" /failure:enable
```

## Troubleshoot

```powershell
& "C:\Program Files\RDP Monitor\rdpmon-svc.exe" status      # elevated prompt
Get-Content "C:\ProgramData\RDP Monitor\logs\service.log" -Tail 50
```

## Upgrade

Install a newer MSI the same way (interactive, `msiexec /i ... /qn`, GPO, Vicarius),
or use **Updates > Check for updates** in the configuration utility. Configuration,
credentials, password, history and queued emails are preserved; downgrades are
refused. See [docs/UPDATES.md](docs/UPDATES.md).

## Remove

Removal is password-protected. Use **Uninstall RDP Monitor** from the Start
menu (or `"C:\Program Files\RDP Monitor\rdpmon-svc.exe" uninstall`), enter the
administration password, and confirm; the service is stopped and the product
is removed. Alternatively, in the configuration utility under **Security**,
enter the password and choose **Uninstall now**, or **Authorize uninstall only**
and then remove *RDP Monitor* in Settings > Apps within 10 minutes.
History and settings in `C:\ProgramData\RDP Monitor` are kept; delete that
folder to erase them (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#removing-all-data)).

## Security

Read [docs/SECURITY.md](docs/SECURITY.md). In short: the password protects RDP
Monitor's own management workflows. A local Administrator controls the operating
system and can ultimately stop or remove any ordinary service; RDP Monitor makes
that deliberate and visible, it cannot prevent it.

## Build

Requirements: Rust (MSVC toolchain), Visual Studio Build Tools, .NET 8 SDK (for WiX 5, restored as a local tool).

```powershell
.\scripts\build.ps1                         # development: tests + dist\RDPMonitor-<version>-x64-unsigned.msi
.\scripts\build.ps1 -Release -ReleaseKey C:\keys\release.key -CertThumbprint <thumbprint>
```

Without both signing options the MSI is named `*-unsigned.msi` and the script
ends with an `UNSIGNED BUILD - not for deployment` warning; `-Release` refuses
to build at all without them. CI (`.github/workflows/ci.yml`, windows-latest)
runs the tests and builds an unsigned MSI on every push and pull request; the
MSI is attached to the workflow run as an artifact.

Testing: [docs/TESTING.md](docs/TESTING.md).
