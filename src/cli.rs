//! Management entry point. Deliberately does not link Packet.dll: diagnostics and
//! service management must remain usable when Npcap is missing.
#[cfg(windows)]
#[path = "windows_service.rs"]
mod windows_service;

use clap::{Parser, Subcommand};
use std::{
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
#[command(
    name = "drcom4scut",
    version,
    about = "SCUT wired network client and Windows service manager"
)]
struct Cli {
    #[arg(short, long, global = true, default_value = "config.yml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Create a configuration template (never overwrites an existing file).
    Init,
    /// List adapters and test Npcap access, without authenticating or sending packets.
    Doctor {
        /// Test opening this adapter; obtain its MAC from the adapter list first.
        #[arg(long)]
        mac: Option<String>,
    },
    /// Run authentication in the foreground.
    Run,
    /// Show the last 60 lines of the authentication log.
    Logs {
        /// Read the installed service log directory (administrator access required).
        #[arg(long)]
        service: bool,
        /// Show service lifecycle and worker restart errors instead of authentication events.
        #[arg(long, requires = "service")]
        supervisor: bool,
    },
    /// Manage the Windows service (install/start/stop/uninstall require administrator).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    #[command(hide = true)]
    ServiceHost,
}

#[derive(Subcommand)]
enum ServiceAction {
    Install,
    Start,
    Stop,
    Status,
    Uninstall,
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("  Cause: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Action::Init => {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cli.config)?;
            file.write_all(include_bytes!("default_config.yml"))?;
            println!(
                "Created {}. Fill in username, password and the wired adapter MAC before running.",
                cli.config.display()
            );
        }
        Action::Doctor { mac } => {
            println!("Worker: {}", worker_path()?.display());
            #[cfg(windows)]
            println!("Npcap directory: {}", npcap_directory()?.display());
            let mut command = worker_command()?;
            command.arg("--check-adapter");
            if let Some(mac) = mac {
                command.args(["--mac", &mac]);
            }
            check_exit(command.status()?)?;
        }
        Action::Run => {
            let path = validated_config(&cli.config, false)?;
            let mut command = worker_command()?;
            command
                .arg("--config")
                .arg(&path)
                .current_dir(path.parent().unwrap());
            check_exit(command.status()?)?;
        }
        Action::Logs {
            service,
            supervisor,
        } => {
            let log_path = if service {
                PathBuf::from(std::env::var_os("ProgramData").ok_or("ProgramData is unavailable")?)
                    .join("drcom4scut/logs")
                    .join(if supervisor {
                        "service.log"
                    } else {
                        "latest.log"
                    })
            } else {
                let path = fs::canonicalize(&cli.config)?;
                let cfg = read_config(&path)?;
                let log_dir = cfg
                    .get_string("log.file_directory")
                    .unwrap_or_else(|_| "logs".into());
                path.parent().unwrap().join(log_dir).join("latest.log")
            };
            println!("Log: {}", log_path.display());
            let text = fs::read_to_string(log_path)?;
            let lines: Vec<_> = text.lines().rev().take(60).collect();
            for line in lines.into_iter().rev() {
                println!("{line}");
            }
        }
        Action::Service { action } => {
            #[cfg(windows)]
            windows_service::manage(action, &cli.config)?;
            #[cfg(not(windows))]
            {
                let _ = action;
                return Err("Windows services are only available on Windows".into());
            }
        }
        Action::ServiceHost => {
            #[cfg(windows)]
            windows_service::dispatch(cli.config)?;
            #[cfg(not(windows))]
            return Err("Windows services are only available on Windows".into());
        }
    }
    Ok(())
}

fn check_exit(status: std::process::ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(
            format!("Authentication worker exited with {status}. Run doctor and inspect the log.")
                .into(),
        )
    }
}

fn read_config(path: &Path) -> Result<config::Config> {
    // Do not forward parser errors: YAML errors can include password source lines.
    config::Config::builder()
        .add_source(config::File::from(path).format(config::FileFormat::Yaml))
        .build()
        .map_err(|_| {
            "Cannot read configuration. Check the file path and YAML syntax (spaces, not tabs)."
                .into()
        })
}

fn validated_config(path: &Path, service: bool) -> Result<PathBuf> {
    let path = fs::canonicalize(path)
        .map_err(|_| "Configuration file not found. Run init, then fill in the configuration.")?;
    let cfg = read_config(&path)?;
    validate_config(&cfg, service)?;
    Ok(path)
}

fn validate_config(cfg: &config::Config, service: bool) -> Result<()> {
    for field in ["username", "password"] {
        if cfg.get_string(field).unwrap_or_default().trim().is_empty() {
            return Err(format!("Configuration field '{field}' is required.").into());
        }
    }
    if let Ok(ip) = cfg.get_string("ip")
        && !ip.trim().is_empty()
        && ip.parse::<std::net::Ipv4Addr>().is_err()
    {
        return Err("Configuration 'ip' must be an IPv4 address.".into());
    }
    if let Ok(mac) = cfg.get_string("mac")
        && !mac.trim().is_empty()
        && !valid_mac(&mac)
    {
        return Err("Configuration 'mac' must use xx:xx:xx:xx:xx:xx format.".into());
    }
    for field in [
        "reconnect",
        "heartbeat.eap_timeout",
        "heartbeat.udp_timeout",
        "retry.interval",
    ] {
        if let Ok(value) = cfg.get::<config::Value>(field)
            && !value.into_int().is_ok_and(|v| (1..=86400000).contains(&v))
        {
            return Err(format!(
                "Configuration '{field}' must be a positive integer (maximum 86400000)."
            )
            .into());
        }
    }
    if let Ok(value) = cfg.get::<config::Value>("retry.count")
        && !value.into_int().is_ok_and(|v| (0..=254).contains(&v))
    {
        return Err("Configuration 'retry.count' must be between 0 and 254.".into());
    }
    if service {
        let mac = cfg.get_string("mac").unwrap_or_default();
        if !valid_mac(&mac) {
            return Err("Service mode requires the wired adapter MAC (xx:xx:xx:xx:xx:xx). Run doctor to list adapters.".into());
        }
        if cfg.get_bool("log.enable_file").ok() == Some(false)
            || cfg
                .get_string("log.level")
                .is_ok_and(|v| v.eq_ignore_ascii_case("off"))
        {
            return Err("Service mode requires file logging: enable log.enable_file and use log.level: INFO.".into());
        }
    }
    Ok(())
}

fn valid_mac(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
        && value != "00:00:00:00:00:00"
        && !value.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff")
}

fn worker_path() -> Result<PathBuf> {
    let name = if cfg!(windows) {
        "drcom4scut-worker.exe"
    } else {
        "drcom4scut-worker"
    };
    let path = std::env::current_exe()?.with_file_name(name);
    if !path.is_file() {
        return Err(format!(
            "Missing {}. Keep both executables in the same directory.",
            path.display()
        )
        .into());
    }
    Ok(path)
}

#[cfg(windows)]
fn system_directory() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = [0u16; 32768];
    let len = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(io::Error::last_os_error().into());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

#[cfg(windows)]
fn npcap_directory() -> Result<PathBuf> {
    let directory = system_directory()?.join("Npcap");
    if !directory.join("Packet.dll").is_file() {
        return Err(
            "Npcap Packet.dll is missing. Install the 64-bit Npcap driver, then run doctor again."
                .into(),
        );
    }
    Ok(directory)
}

fn worker_command() -> Result<Command> {
    let mut command = Command::new(worker_path()?);
    #[cfg(windows)]
    {
        // Packet.dll is an implicit dependency of libpnet, loaded before worker
        // main. Setting its search path in the worker itself would be too late.
        let mut paths = vec![npcap_directory()?];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        command.env("PATH", std::env::join_paths(paths)?);
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_rejects_ambiguous_or_invalid_identifiers() {
        assert!(valid_mac("a0:B1:c2:d3:e4:f5"));
        for bad in [
            "",
            "0:1:2:3:4:5",
            "aa:bb:cc:dd:ee:gg",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "aa-bb-cc-dd-ee-ff",
        ] {
            assert!(!valid_mac(bad));
        }
    }
    #[test]
    fn cli_accepts_global_config_and_nested_service_commands() {
        let cli = Cli::try_parse_from([
            "drcom4scut",
            "service",
            "install",
            "--config",
            "C:\\path with spaces\\config.yml",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Action::Service {
                action: ServiceAction::Install
            }
        ));
        assert_eq!(
            cli.config,
            PathBuf::from("C:\\path with spaces\\config.yml")
        );
        assert!(
            Cli::try_parse_from(["drcom4scut", "doctor", "--mac", "aa:bb:cc:dd:ee:ff"]).is_ok()
        );
    }
    #[test]
    fn unattended_config_requires_adapter_credentials_and_sensible_timers() {
        fn cfg(extra: &str) -> config::Config {
            config::Config::builder()
                .add_source(config::File::from_str(
                    &format!("username: test\npassword: do-not-print-this-secret\n{extra}"),
                    config::FileFormat::Yaml,
                ))
                .build()
                .unwrap()
        }
        assert!(validate_config(&cfg("mac: 'a0:b1:c2:d3:e4:f5'"), true).is_ok());
        for extra in [
            "",
            "mac: bad",
            "reconnect: -1",
            "heartbeat:\n  udp_timeout: 0",
            "retry:\n  count: 255",
            "ip: '::1'",
            "mac: 'a0:b1:c2:d3:e4:f5'\nlog:\n  enable_file: false",
        ] {
            let error = validate_config(&cfg(extra), true).unwrap_err().to_string();
            assert!(!error.contains("do-not-print-this-secret"));
        }
        assert!(validate_config(&cfg("reconnect: 15"), false).is_ok());
    }
}
