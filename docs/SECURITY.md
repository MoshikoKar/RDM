# Security model

## Scope

RDP Monitor protects **its own management workflows**: who may change its
settings, read its secrets, update it or remove it through the supported tools.
It runs as an ordinary Windows service. On a computer where users are local
Administrators, those users control the operating system and can ultimately
stop, modify or remove any ordinary service. RDP Monitor makes that deliberate,
noisier and auditable; **it cannot prevent it**, and it does not use kernel
drivers, stealth techniques or watchdog processes to try.

## What is protected, and how

| Asset | Protection |
|---|---|
| Settings and secrets at rest | One TOML document encrypted with **DPAPI for the SYSTEM account** (plus application entropy) in `C:\ProgramData\RDP Monitor\config.dat`. DPAPI also detects modification. Only code running as SYSTEM can decrypt it. Previous version kept as `config.dat.bak`. |
| Data directory | Protected DACL: SYSTEM full control, Administrators read-only, no access for users. |
| Administration password | Never stored; only an **Argon2id** verifier (19 MiB, t=2, p=1, random salt). Minimum 10 characters from 3 character classes. |
| Sign-in | 5 free attempts, then lockout 30 s, doubling up to 15 min. Every failure audited. Sessions expire after 15 min idle, are bound to the client process, and are invalidated by a password change. |
| Admin interface | Named pipe `\\.\pipe\RDPMonitor.Admin`: SYSTEM and **elevated** Administrators only, network logons denied, remote clients rejected, no network port. The service creates it with `FILE_FLAG_FIRST_PIPE_INSTANCE`; the client refuses to talk to a pipe not served by the `RDPMonitor` service process (anti-squatting). 30 s I/O timeout, 4 MiB message limit. |
| Secrets in transit to the UI | The SMTP password and update token are never sent to the UI. A stored secret is never reused for a different SMTP server/user or update host: changing those requires re-entering the secret, so a session cannot redirect stored credentials to an attacker's server. |
| Configuration packages | Ed25519 signature with the trusted key; monotonic serial prevents replay or rollback; full validation before applying; trusted key rotatable only with the current key. The installer's `TRUSTED_CONFIG_KEY` is honoured only on a never-configured agent (an MSI repair cannot install a new key). A package cannot remove the administration password, and a stored SMTP password / update token is dropped when a package changes their destination without supplying a new secret. Password hashes with excessive Argon2 cost parameters are refused. |
| Loss of the configuration | A marker in the SYSTEM-only database records that the agent was set up; losing `config.dat` never re-opens unauthenticated first-run setup. |
| Detection evasion | Service identities are excluded by their domain (`NT AUTHORITY`, `Window Manager`, `Font Driver Host`), never by user-name patterns, so naming an account `x$` or `DWM-1` does not hide an RDP session. Loopback connections (RDP through a local tunnel) are recorded and notified by default. |
| Updates | See [UPDATES.md](UPDATES.md#trust-model): offline Ed25519 signature over file name + version + SHA-256; downgrades refused; token sent only to the configured host. |
| Service | Automatic start; recovery restarts after 1, 1 and 2 minutes (also for non-crash failures). Optional hardened service DACL (default on): Administrators can query and start the service but not stop, reconfigure or delete it through the SCM; SYSTEM (MSI, GPO, deployment tools) keeps full control. |
| Removal | The MSI refuses to uninstall unless removal was authorized with the administration password (UI *Uninstall now*, Start menu uninstaller, or `rdpmon-svc uninstall` / authorize-uninstall) or by a signed package, within the last 10 minutes. Upgrades are not affected. |
| Audit | Sign-ins and failures, configuration changes (which sections, by which Windows user/process), packages applied or rejected, test emails, update checks/installs, uninstall authorizations and attempts, service start/stop, subscription interruptions, delivery failures. Kept 365 days (configurable). |
| Logs and errors | Never contain passwords or tokens. Secrets are not accepted on command lines or in environment variables. |
| Email content | Subject placeholders are stripped of control characters (no header injection); all values in HTML are escaped. |

## What a local Administrator can still do

Being explicit, so nobody relies on protection that does not exist:

- **Run code as SYSTEM** (e.g. `psexec -s`, a scheduled task as SYSTEM, a
  service they install). As SYSTEM they can decrypt `config.dat`, read the SMTP
  password, change any setting and stop or delete the service.
- **Take ownership** (`SeTakeOwnershipPrivilege`) of the service object, its
  registry key or the data directory, then change the permissions.
- **Kill the process** (`SeDebugPrivilege`). The SCM restarts it within a
  minute and the service recovers the missed events from the event log through
  its bookmarks, unless the logs were cleared in the meantime.
- **Delete or corrupt `config.dat` and its backup**: monitoring and history
  continue, email stops. The agent does **not** fall back to first-run setup
  (that would let anyone set a new password); it stays locked until someone
  running as SYSTEM executes `rdpmon-svc reset` (audited), after which setup can
  be completed again. A local administrator who can run code as SYSTEM can do
  this too - it is the same boundary as above.
- **Bypass the uninstall gate**, e.g. by setting `UPGRADINGPRODUCTCODE` on the
  msiexec command line, or replace the binaries in `C:\Program Files\RDP Monitor`
  (Program Files is writable by Administrators).
- **Lock out the legitimate administrator** temporarily by repeatedly entering
  wrong passwords: the sign-in rate limit is per computer, not per user.
- **Disable auditing** or **clear the event logs**, which removes the source data.
- **Remove the product** by bypassing the MSI (`sc delete` after taking
  ownership, editing the cached MSI, deleting files).
- **Use RDP Monitor's own interface** if they know the administration password.

## Recommended controls for stronger resistance

If RDP Monitor must withstand users who are local administrators, the solution
is in Windows administration, not in the agent:

1. **Remove standing local administrator rights** (separate admin accounts,
   Windows LAPS, just-in-time elevation).
2. **Centralize the evidence**: forward Security and TerminalServices events to
   a collector/SIEM with Windows Event Forwarding, and alert on
   1102 (Security log cleared), 104 (other log cleared), 4719 (audit policy
   changed), 7045 (service installed), 7036/7040 (service stopped / start type
   changed), 4697 (service installed, if audited).
3. **Watch for silence**: enable the daily heartbeat (`[heartbeat]`) - a
   computer whose heartbeat stops arriving, or arrives as WARNING, needs
   investigation. Without it, the weekly report is the only sign of life.
4. **Application control** (WDAC / AppLocker) to block tools such as PsExec on
   workstations.
5. Protect the deployment share, the signing keys and the GPOs; whoever controls
   them controls every agent.

## Data stored

Per connection: time, computer name, user name and domain, source IP, session
ID (when available), Windows event IDs, notification outcome. No passwords,
process data, keystrokes or screen content. History is deleted after
`retention.history_days` (default 365). Notification and report emails contain
the same fields.

## Network traffic

| When | Destination | Content |
|---|---|---|
| Normal operation | Configured SMTP server only | Alert and report emails |
| Administrator clicks *Check for updates* / *Download and install* | Configured GitHub/GitLab host (and the download host it redirects to) | HTTPS requests for release metadata and the MSI + signature |

There is no telemetry, analytics, inter-agent communication, remote control or
automatic update check. The update host (and any proxy in between) necessarily
learns: the computer's public/source IP address, the time of the check, the
`User-Agent` (`RDPMonitor-Updater/<installed version>`), the repository and
asset paths requested, the TLS server name, and - for private repositories -
the access token presented. No history, user names, SMTP settings or other
configuration are sent. Redirects are followed only over HTTPS, at most 5 hops,
and the token is never sent to a host (or port) other than the configured one.
WinHTTP automatic logon is disabled, so the computer account never answers an
NTLM/Negotiate challenge from the update host (proxies that require Windows
authentication are therefore not supported for updates).

Use a read-only token (GitHub fine-grained token with *Contents: read*; GitLab
project access token with role Reporter and scope `read_api`) dedicated to
updates.
