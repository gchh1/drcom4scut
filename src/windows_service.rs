use super::{Result, ServiceAction, validated_config, worker_command, worker_path};
use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::windows::{io::AsRawHandle, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::{OnceLock, mpsc},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::*,
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{JobObjects::*, Threading::CREATE_NO_WINDOW},
};

const NAME: &str = "drcom4scut";
static CONFIG: OnceLock<PathBuf> = OnceLock::new();
define_windows_service!(service_entry, service_main);

pub fn manage(action: ServiceAction, config: &Path) -> Result<()> {
    let access = if matches!(action, ServiceAction::Install) {
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE
    } else {
        ServiceManagerAccess::CONNECT
    };
    let manager = ServiceManager::local_computer(None::<&str>, access)?;
    match action {
        ServiceAction::Install => {
            if !cfg!(feature = "log4rs") {
                return Err(
                    "Service installation requires a build with the default log4rs feature.".into(),
                );
            }
            let config = validated_config(config, true)?;
            worker_path()?;
            super::npcap_directory()?;
            if manager
                .open_service(NAME, ServiceAccess::QUERY_STATUS)
                .is_ok()
            {
                return Err("Service already exists. Stop and uninstall it before installing a new version.".into());
            }
            // Use a fixed, protected directory: the service runs as LocalSystem.
            // Do not execute a user-writable build-tree binary at boot.
            let base =
                PathBuf::from(std::env::var_os("ProgramData").ok_or("ProgramData is unavailable")?)
                    .join(NAME);
            if base.exists() {
                return Err(format!("{} already exists. Preserve its configuration/logs and choose an explicit upgrade before reinstalling.", base.display()).into());
            }
            fs::create_dir(&base)?;
            let system = super::system_directory()?;
            let status = std::process::Command::new(system.join("icacls.exe"))
                .arg(&base)
                .args([
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status()?;
            if !status.success() {
                return Err("Could not protect service directory. Installation stopped.".into());
            }
            let executable = base.join("drcom4scut.exe");
            fs::copy(std::env::current_exe()?, &executable)?;
            fs::copy(worker_path()?, base.join("drcom4scut-worker.exe"))?;
            let installed_config = base.join("config.yml");
            // Keep service logs inside the protected installation directory,
            // independent of the user's foreground log settings.
            let mut content = fs::read_to_string(&config)?;
            if !content.ends_with('\n') {
                content.push('\n');
            }
            fs::write(&installed_config, content)?;
            let service = manager.create_service(
                &ServiceInfo {
                    name: NAME.into(),
                    display_name: "SCUT wired network authentication".into(),
                    service_type: ServiceType::OWN_PROCESS,
                    start_type: ServiceStartType::AutoStart,
                    error_control: ServiceErrorControl::Normal,
                    executable_path: executable,
                    launch_arguments: vec![
                        "--config".into(),
                        installed_config.into_os_string(),
                        "service-host".into(),
                    ],
                    dependencies: vec![],
                    account_name: None,
                    account_password: None,
                },
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
            )?;
            service.set_description("Authenticate SCUT wired network before Windows sign-in and recover after disconnects.")?;
            service.update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![windows_service::service::ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(15),
                }]),
            })?;
            service.set_failure_actions_on_non_crash_failures(true)?;
            println!(
                "Installed automatic service. Protected files: {}",
                base.display()
            );
            println!(
                "Run service start to connect now. Installation alone does not start authentication."
            );
        }
        ServiceAction::Start => {
            manager
                .open_service(NAME, ServiceAccess::START)?
                .start::<OsString>(&[])?;
            println!("Start requested. Use service status and logs to check authentication.");
        }
        ServiceAction::Stop => {
            let service =
                manager.open_service(NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
            if service.query_status()?.current_state != ServiceState::Stopped {
                service.stop()?;
            }
            wait_stopped(&service)?;
            println!("Service stopped.");
        }
        ServiceAction::Status => {
            let service = manager.open_service(
                NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
            )?;
            let status = service.query_status()?;
            println!(
                "Service: {:?}; PID: {:?}; exit: {:?}",
                status.current_state, status.process_id, status.exit_code
            );
            println!(
                "Service running does not prove campus authentication or Internet access. Inspect the recent log."
            );
            println!(
                "Installed command: {}",
                service.query_config()?.executable_path.display()
            );
            println!(
                "Service logs: %ProgramData%\\drcom4scut\\logs (administrator access required)"
            );
        }
        ServiceAction::Uninstall => {
            let service =
                manager.open_service(NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?;
            if service.query_status()?.current_state != ServiceState::Stopped {
                return Err("Stop the service before uninstalling it.".into());
            }
            service.delete()?;
            println!(
                "Service removed. Protected configuration, executables and logs are retained in %ProgramData%\\drcom4scut."
            );
        }
    }
    Ok(())
}

fn wait_stopped(service: &Service) -> Result<()> {
    for _ in 0..100 {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Service has not stopped within 10 seconds; query status before trying again.".into())
}

pub fn dispatch(path: PathBuf) -> Result<()> {
    CONFIG
        .set(path)
        .map_err(|_| "Service already initialized")?;
    service_dispatcher::start(NAME, service_entry)?;
    Ok(())
}

fn service_main(_: Vec<OsString>) {
    if let Err(error) = run_service() {
        if let Some(path) = CONFIG.get() {
            record(path, &format!("Service failure: {error}"));
        }
        // Non-zero process exit lets SCM apply the configured recovery action.
        std::process::exit(1);
    }
}

fn status(state: ServiceState, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: if state == ServiceState::StopPending {
            1
        } else {
            0
        },
        wait_hint: Duration::from_secs(5),
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let path = CONFIG.get().ok_or("Missing service configuration path")?;
    let (tx, rx) = mpsc::channel();
    let handle = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running, 0))?;
    let job = Job::new()?;
    record(path, "Service started; waiting for authentication worker.");
    let mut child: Option<Child> = None;
    let mut retry_at = std::time::Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let Some(worker) = child.as_mut()
            && let Some(exit) = worker.try_wait()?
        {
            record(
                path,
                &format!(
                    "Worker exited: {exit}; retry in 15 seconds. Check worker-errors.log and latest.log."
                ),
            );
            child = None;
            retry_at = std::time::Instant::now() + Duration::from_secs(15);
        }
        if child.is_none() && std::time::Instant::now() >= retry_at {
            match spawn_worker(path, &job) {
                Ok(worker) => {
                    record(path, &format!("Worker started; PID {}.", worker.id()));
                    child = Some(worker);
                }
                Err(error) => {
                    record(
                        path,
                        &format!("Cannot start worker: {error}; retry in 15 seconds."),
                    );
                    retry_at = std::time::Instant::now() + Duration::from_secs(15);
                }
            }
        }
    }
    handle.set_service_status(status(ServiceState::StopPending, 0))?;
    if let Some(mut worker) = child {
        let _ = worker.kill();
        let _ = worker.wait();
    }
    drop(job);
    record(path, "Service stopped; authentication worker terminated.");
    handle.set_service_status(status(ServiceState::Stopped, 0))?;
    Ok(())
}

fn spawn_worker(path: &Path, job: &Job) -> Result<Child> {
    let path = validated_config(path, true)?;
    let directory = path.parent().unwrap();
    fs::create_dir_all(directory.join("logs"))?;
    let errors = directory.join("logs/worker-errors.log");
    rotate(&errors);
    let stderr = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(errors)?;
    let mut child = worker_command()?
        .arg("--config")
        .arg(&path)
        .arg("--service-worker")
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    if unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) } == 0 {
        let error = std::io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    Ok(child)
}

fn rotate(path: &Path) {
    if fs::metadata(path).is_ok_and(|m| m.len() > 1024 * 1024) {
        let old = path.with_extension("old.log");
        if old.exists() {
            let _ = fs::remove_file(&old);
        }
        let _ = fs::rename(path, old);
    }
}

fn record(config: &Path, message: &str) {
    let dir = config.parent().unwrap_or(Path::new(".")).join("logs");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("service.log");
    rotate(&path);
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{} {message}", chrono::Local::now().to_rfc3339());
    }
}

struct Job(HANDLE);
impl Job {
    fn new() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let job = Self(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(job)
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_stop_does_not_leave_an_orphan_worker() {
        let job = Job::new().unwrap();
        let system = super::super::system_directory().unwrap();
        let mut child =
            std::process::Command::new(system.join("WindowsPowerShell/v1.0/powershell.exe"))
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 30",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .unwrap();
        let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) };
        if assigned == 0 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Cannot assign test child to job");
        }
        drop(job);
        for _ in 0..50 {
            if child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("Worker survived closure of service job");
    }
}
