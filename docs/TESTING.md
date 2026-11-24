# Testing

## Automated tests

```powershell
cargo test --workspace                      # 69 tests, ~10 s after build
cargo test -p rdpmon-svc -- --ignored       # + live GitHub API test (needs internet)
```

They run as an ordinary (non-elevated) user. Tests marked *live* use real
Windows components rather than mocks.

| Requirement | Tests |
|---|---|
| New RDP logon detection | `events::parses_4624_type_10`, `correlate::new_logon_events_merge_into_one_connection` |
| Reconnection detection | `events::parses_reconnect_disconnect_and_lsm`, `correlate::reconnect_wins_over_logon_in_same_group` |
| Ignore non-RDP / built-in identities; no evasion by account name | `events::ignores_non_rdp_and_system_logons` |
| Authentication alone is not a session | `correlate::authentication_alone_is_not_a_connection` |
| Duplicate event suppression | `correlate::same_record_read_twice_is_ignored`, `correlate::repeated_event_type_starts_a_new_connection`, `correlate::different_users_or_ips_are_separate`, `db::records_history_dedupe_and_cooldown` |
| Notification cooldown and types | `notify::cooldown_policy`, `notify::notification_types_and_smtp` |
| Event subscription, restart recovery (live) | `evt::live_subscription_and_bookmark_recovery` (real Application log: real-time delivery, then recovery of an event written while unsubscribed), `evt::recovery_without_bookmark`, `evt::missing_channel_fails_cleanly`, `monitor::production_queries_are_accepted_by_windows` (Windows parses the production XPath queries) |
| SMTP success / auth failure / rejection / connection failure; rejected message does not block the queue | `mail::*` (scripted SMTP server on localhost) |
| Retry, backoff, queue limits, queue persistence | `db::outbox_retry_send_fail_and_limits`, `db::queue_survives_reopen`, `delivery::backoff_is_exponential_and_capped` |
| Weekly report content and schedule | `notify::report_aggregates`, `notify::report_schedule` |
| Invalid configuration | `config::invalid_settings_are_reported`, `config::unknown_keys_are_rejected`, `handler::save_config_rules` |
| Password verification, rate limiting | `password::*`, `auth::*`, `handler::login_rate_limit_and_session_binding` |
| Unauthorized configuration changes | `handler::unauthorized_changes_are_rejected_and_audited`, `handler::first_run_setup_then_locked_down`, `handler::save_config_rules` (secret redirection refused) |
| Protected credential storage (live DPAPI), atomic save, backup never overwritten by a corrupt file | `crypto::dpapi_roundtrip_and_tamper_detection`, `store::save_load_backup_and_tamper` |
| Lost configuration does not re-open setup | `handler::lost_configuration_does_not_reopen_first_run_setup` |
| Signed configuration packages (incl. secrets not following a changed destination, bounded Argon2 parameters) | `package::*`, `password::hash_and_verify`, `handler::signed_package_import`, `handler::signed_package_can_authorize_silent_uninstall_once` |
| Update signature verification | `release::release_signature` |
| Update source handling | `update::github_selection_skips_drafts_prereleases_and_unsigned`, `update::gitlab_parsing_rejects_foreign_asset_hosts`, `update::sources`, `update::live_github_check` (live WinHTTP/TLS; 404 for a missing repository) |
| Uninstall authorization | `handler::uninstall_requires_authorization` |
| Email injection / HTML escaping | `notify::alert_rendering_escapes_and_sanitizes`, `config::email_syntax` |
| Security descriptors | `winsec::sddl_strings_parse` |

## Verified in the development environment

Windows 11, non-elevated user account, Rust 1.99, WiX 5.0.2:

- All automated tests above pass, including the live tests.
- Release service binary run in console mode (`rdpmon-svc console --data-dir <tmp>`):
  subscribed to the LocalSessionManager and RemoteConnectionManager channels;
  Security log correctly reported *access denied* (non-elevated) and retried every
  60 s without affecting the other channels.
- **Idle resource use (release build, 60 s): 0.0 ms CPU, 9.0 MB working set,
  1.5 MB private bytes, 6 threads.** Binary sizes: service 3.5 MB, MSI 7.1 MB.
- This smoke test found and fixed a real bug (EvtNext error 4317 on a healthy
  pull subscription caused a 5-second re-subscribe loop).
- Configuration utility: every page and the setup wizard rendered and checked by
  screenshot (software renderer, Fluent style, follows the Windows theme).
- `rdpmon-tool`: key generation, config package sign/verify (wrong key rejected),
  release sign/verify (tampered MSI rejected).
- MSI built; tables inspected: service definition, `CheckUninstall` before
  `StopServices`, `ProvisionAgent` before `StartServices`,
  `RemoveExistingProducts` right after `InstallInitialize`.
- GPO transform generated and verified by applying it to a copy of the MSI.

## Independent code review

A separate reviewer audited the service, protocol and installer for security
and correctness. All confirmed findings were fixed and covered by tests where
testable: fail-open to first-run setup when the configuration is unreadable;
non-durable configuration save that could also overwrite a good backup; events
lost across a restart before a channel had a bookmark; duplicate emails / SMTP
hammering on database errors; admin pipe blockable by a client that never reads
(and audit records without the caller's identity); detection evasion via
account names and loopback; MSI repair able to install a new trusted key;
packages able to redirect stored secrets or clear the password; stop and
recovery-policy gaps; WinHTTP automatic logon; queue head-of-line blocking.
Accepted and documented instead of fixed: global (not per-user) sign-in lockout,
uninstall-gate bypass via `UPGRADINGPRODUCTCODE`, replaceable binaries in Program
Files (see SECURITY.md); a configuration-utility session left open while a package
changes the trusted key can write the old key back on its next Save.

## Verification gaps (not tested here)

The development account was not elevated, and installing services on that
workstation was out of scope. **The following have not been executed and must
be validated on a test VM before rollout:**

- Running under the Service Control Manager as LocalSystem; recovery actions;
  service DACL hardening effect; DPAPI under the SYSTEM account.
- Subscription to the **Security** log and detection of **real RDP sessions**
  (event parsing is tested with representative event XML, not captured events).
- End-to-end named-pipe administration with the elevated configuration utility
  (the request handler is tested directly; the pipe transport is not).
- Delivery through a real SMTP server with STARTTLS / implicit TLS and
  authentication (tests use a plain-TCP scripted server).
- MSI interactive install and setup wizard launch, silent install with
  `TRUSTED_CONFIG_KEY` / `CONFIG_PACKAGE`, upgrade 0.1.1 → 0.1.x with data
  preservation, rollback, downgrade refusal, authorized and unauthorized removal.
- In-app update download + msiexec hand-off.
- GPO Software Installation, GPO startup script, Vicarius.
- Windows Server 2016/2019/2022/2025 and Windows 10.

## Manual test procedure (test VM with real RDP)

Prerequisites: a Windows test VM with RDP enabled, a second computer to connect
from, an SMTP server or test mailbox you can read, the MSI from `dist\`.
Enable reconnect auditing for 4778/4779:
`auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable`.

| # | Action | Expected result |
|---|---|---|
| 1 | Install the MSI interactively; keep *Open the setup wizard* ticked. | Service `RDP Monitor` running (`Get-Service RDPMonitor`). Wizard opens (UAC prompt). |
| 2 | Complete the wizard; click *Send test email* on step 5; Finish. | Test email arrives. General page shows all three channels *active*. |
| 3 | Set quiet period to 0, save. RDP into the VM as a domain/local user. | Within ~5 s: one email, type *New login*, correct user, source IP, time. History shows one row with event IDs (e.g. `21, 1149, 4624`). |
| 4 | Disconnect (close the RDP window), reconnect. | History: one *disconnect* row (no email), one *reconnect* row, one email *Reconnection*. |
| 5 | Set quiet period to 15, reconnect twice quickly. | Both recorded in history; the second shows *suppressed: cooldown*; no second email. |
| 6 | `rdpmon-svc status` (elevated); `sc stop RDPMonitor` (elevated). | Status lists channels and queue. With hardening on, `sc stop` fails with *Access is denied*. Untick hardening in Security, save, `sc stop` works. |
| 7 | With the service stopped, RDP in; then `sc start RDPMonitor`. | Email for the missed connection marked *recovered after the service was restarted*. |
| 8 | Change SMTP host to an unreachable address, save, RDP in. Restart the service. Restore the host, save. | Connection recorded immediately; General shows 1 waiting + last problem. Item survives restart. After fixing, email arrives within seconds. Audit shows *email delivery failing* then *restored*. |
| 9 | Change recipients in the UI and save while connected via RDP. | Applied without restarting; next email goes to the new list; monitoring uninterrupted. |
| 10 | Wrong password 6 times. | Lockout message; audit shows the failures with the Windows user name. |
| 11 | Uninstall from Settings > Apps without authorization. | Fails; audit shows *uninstall blocked*. Authorize in Security, uninstall again: succeeds. |
| 12 | Silent: `msiexec /i ... /qn TRUSTED_CONFIG_KEY=... CONFIG_PACKAGE=...` | Exit 0; settings from the package visible in the UI; audit *provisioned by installer*. A package signed with another key: exit 1603, nothing installed. |
| 13 | Build version 0.1.2 (edit `Cargo.toml`), install over 0.1.1 silently. | Exit 0; settings, password, history, queue unchanged; audit *service started version 0.1.2*. Installing 0.1.1 again: exit 1638. |
| 14 | Publish 1.0.2 + `.sig` to a test GitHub/GitLab release; *Check for updates*, *Download and install*. | Release notes shown; service restarts on 1.0.2; audit *update installed*. Replace the MSI asset with an unsigned/modified one: *Update rejected*. |
| 15 | `rdpmon-svc import` a newer package; again with the same file; then an older one. | Exit 0 (applied); exit 0 (already applied); exit 4 (rejected). |

### Measuring resource use

```powershell
$p = Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='RDPMonitor'").ProcessId
$c0 = $p.TotalProcessorTime; Start-Sleep 300; $p.Refresh()
"CPU ms in 5 min: {0:N0}; working set {1:N1} MB; private {2:N1} MB; handles {3}; threads {4}" -f `
  ($p.TotalProcessorTime - $c0).TotalMilliseconds, ($p.WorkingSet64/1MB), ($p.PrivateMemorySize64/1MB), $p.HandleCount, $p.Threads.Count
```

Record values idle, and again after 10 RDP connect/disconnect cycles, and after
24 h, to confirm there is no growth. Record results and any limitations found
in this document.
