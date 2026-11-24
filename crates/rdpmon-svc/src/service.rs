//! Windows Service Control Manager integration.

use crate::app::{self, Shared};
use crate::logging;
use rdpmon_core::paths::SERVICE_NAME;
use std::ffi::OsString;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> i32 {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rdpmon-svc service: must be started by the Service Control Manager ({e}). Use 'rdpmon-svc help'.");
            1
        }
    }
}

fn set(h: &ServiceStatusHandle, state: ServiceState, accept: ServiceControlAccept, exit: ServiceExitCode, wait: Duration) {
    let _ = h.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    });
}

fn service_main(_args: Vec<OsString>) {
    let cell: Arc<OnceLock<Arc<Shared>>> = Arc::new(OnceLock::new());
    let handle_cell: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let (c2, h2) = (cell.clone(), handle_cell.clone());
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(h) = h2.get() {
                set(h, ServiceState::StopPending, ServiceControlAccept::empty(), ServiceExitCode::Win32(0), Duration::from_secs(50));
                // Workers can be inside a blocking SMTP/HTTP call (bounded by
                // their own timeouts). Never let a stop hang beyond 45 s; all
                // state is persisted transactionally, so exiting is safe.
                let h = *h;
                let _ = std::thread::Builder::new().spawn(move || {
                    std::thread::sleep(Duration::from_secs(45));
                    logging::warn("workers did not stop within 45 s; exiting");
                    set(&h, ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::Win32(0), Duration::ZERO);
                    std::process::exit(0);
                });
            }
            if let Some(s) = c2.get() {
                s.request_stop();
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(SERVICE_NAME, handler) else { return };
    let _ = handle_cell.set(h);
    set(&h, ServiceState::StartPending, ServiceControlAccept::empty(), ServiceExitCode::Win32(0), Duration::from_secs(15));

    // Before anything that can fail, so a failed first start is also restarted.
    configure_recovery();
    match crate::startup(None, true) {
        Ok(shared) => {
            let _ = cell.set(shared.clone());
            app::apply_service_hardening(shared.cfg().security.harden_service);
            set(&h, ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0), Duration::ZERO);
            logging::info(&format!("RDP Monitor {} running on {}", rdpmon_core::VERSION, shared.host));
            app::run(shared.clone());
            if let Ok(db) = shared.open_db() {
                let _ = db.audit("service", "service stopped", "normal stop");
            }
            logging::info("service stopped");
            set(&h, ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::Win32(0), Duration::ZERO);
        }
        Err(e) => {
            logging::error(&format!("service failed to start: {e}"));
            // Non-zero exit makes the SCM apply the recovery (restart) policy.
            set(&h, ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::ServiceSpecific(1), Duration::ZERO);
        }
    }
}

/// Restart after 1 min, 1 min, then 2 min; reset the failure count daily.
/// Also applies to non-crash failures (service stopping with an error code).
fn configure_recovery() {
    let r = (|| -> windows_service::Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
        let restart = |s| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(s) };
        svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(60), restart(60), restart(120)]),
        })?;
        svc.set_failure_actions_on_non_crash_failures(true)
    })();
    if let Err(e) = r {
        logging::warn(&format!("could not configure service recovery: {e}"));
    }
}

/// True if the RDP Monitor service is installed and running.
pub fn is_running() -> bool {
    (|| -> windows_service::Result<bool> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
        Ok(svc.query_status()?.current_state != ServiceState::Stopped)
    })()
    .unwrap_or(false)
}
