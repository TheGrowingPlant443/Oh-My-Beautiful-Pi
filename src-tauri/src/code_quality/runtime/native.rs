//! Linux and macOS container runtimes. There is no WSL and no app-provisioned VM here:
//!
//! * Linux: native (rootless) Podman, which is daemonless, and native Docker Engine.
//! * macOS: Podman through the user's own `podman machine` and Docker Desktop. A Podman selection is
//!   bound to its machine by the connection's live SSH endpoint and identity, never by name.
//!
//! The app never installs a container engine and never creates a Podman machine. It detects, probes
//! and explains. A missing or stopped engine is an actionable `Err`, never a silent fallback to
//! another runtime.
use super::cli_engine::{self, CliEngine, Engine, EngineProbe, RunControl, PROBE_TIMEOUT};
#[cfg(any(target_os = "macos", test))]
use crate::code_quality::install::{self, MachineBinding, PodmanTarget};
use crate::code_quality::types::{Prerequisite, QualityOptions, QualityRuntime, Result};
use serde_json::Value;
#[cfg(any(not(target_os = "macos"), test))]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const MIN_MAP_COUNT: u64 = 524_288;
const MIN_FILE_MAX: u64 = 131_072;

/// Where engine clients usually live outside a login shell's PATH.
fn standard_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        dirs.push(home.join(".nix-profile/bin"));
        dirs.push(home.join(".local/state/nix/profile/bin"));
        dirs.push(home.join(".local/bin"));
    }
    dirs.extend(
        [
            "/run/current-system/sw/bin",
            "/nix/var/nix/profiles/default/bin",
            "/usr/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/opt/podman/bin",
        ]
        .map(PathBuf::from),
    );
    dirs
}

fn program(name: &str) -> Option<PathBuf> {
    cli_engine::discover_program(
        name,
        &standard_dirs()
            .iter()
            .map(|dir| dir.join(name))
            .collect::<Vec<_>>(),
    )
}

pub(super) fn podman_program() -> Option<PathBuf> {
    program("podman")
}
pub(super) fn docker_program() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = standard_dirs()
        .into_iter()
        .map(|dir| dir.join("docker"))
        .collect();
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            candidates.push(home.join(".docker/bin/docker"));
            candidates.push(home.join("Applications/Docker.app/Contents/Resources/bin/docker"));
        }
        candidates.push("/Applications/Docker.app/Contents/Resources/bin/docker".into());
    }
    cli_engine::discover_program("docker", &candidates)
}

#[must_use]
pub(crate) fn macos() -> bool {
    cfg!(target_os = "macos")
}

#[must_use]
pub(crate) fn missing_podman() -> String {
    if macos() {
        "Podman is not installed. Install the Podman CLI with Nix (`nix --extra-experimental-features 'nix-command flakes' profile add nixpkgs#podman`), then create and start a Podman machine yourself (for example `podman machine init --now`) and Recheck. A machine is required on macOS; OMP Manager never installs software or creates machines on macOS.".into()
    } else {
        "Podman is not installed. Install it (Nix: `nix profile add nixpkgs#podman`; Debian/Ubuntu: `apt install podman`; Fedora: `dnf install podman`; Arch: `pacman -S podman`) and make sure rootless containers work (`podman info`), then Recheck. OMP Manager never installs container engines.".into()
    }
}

#[must_use]
pub(crate) fn missing_docker() -> String {
    if macos() {
        "Docker Desktop is not installed. Install it from https://www.docker.com/products/docker-desktop/ (or Homebrew: `brew install --cask docker`), start it and Recheck. OMP Manager never installs software on macOS.".into()
    } else {
        "Docker is not installed. Install Docker Engine for your distribution (https://docs.docker.com/engine/install/), start its service, add your user to the `docker` group and Recheck. OMP Manager never installs container engines.".into()
    }
}

/// Maps a selection to the concrete client invocation. Only the runtimes of this platform resolve.
pub(super) fn resolve(runtime: QualityRuntime) -> Result<(QualityRuntime, PathBuf, Vec<String>)> {
    match runtime {
        QualityRuntime::Podman { connection } => {
            let prefix = if connection.is_empty() { Vec::new() } else {
                cli_engine::validate_selector(&connection, "Podman connection")?;
                vec!["--connection".into(), connection.clone()]
            };
            Ok((QualityRuntime::Podman { connection }, podman_program().ok_or_else(missing_podman)?, prefix))
        }
        QualityRuntime::DockerNative if !macos() => {
            Ok((QualityRuntime::DockerNative, docker_program().ok_or_else(missing_docker)?, Vec::new()))
        }
        QualityRuntime::DockerNative => Err("Native Docker Engine is only available on Linux; on macOS choose Docker Desktop or Podman.".into()),
        QualityRuntime::DockerDesktop if macos() => {
            Ok((QualityRuntime::DockerDesktop, docker_program().ok_or_else(missing_docker)?,
                vec!["--context".into(), "desktop-linux".into()]))
        }
        QualityRuntime::DockerDesktop => Err("Docker Desktop is not offered on Linux; choose Docker (native Engine) or Podman.".into()),
        QualityRuntime::DockerWsl { .. } => Err("Docker in WSL is only available on Windows.".into()),
    }
}

/// What an engine's `info` JSON says, reduced to the facts the lifecycle needs.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Info {
    pub os: String,
    pub id: String,
    pub graph: String,
    pub memory_bytes: u64,
    pub remote: bool,
    pub operating_system: String,
    /// Why `--cpus` cannot be honoured by this engine (`None`: it can, or nothing says it cannot).
    pub cpu_limits_unsupported: Option<String>,
}

pub(super) fn parse_podman_info(v: &Value) -> Result<Info> {
    let host = v.get("host").ok_or("Invalid Podman info response.")?;
    let rootless = host
        .pointer("/security/rootless")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let controllers: Option<Vec<&str>> = host
        .get("cgroupControllers")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect());
    // Rootless cgroup v2 only gets the controllers systemd delegated to the user. `--cpus` needs `cpu`.
    let cpu_limits_unsupported = match (&controllers, rootless) {
        (Some(list), true) if !list.contains(&"cpu") => Some(format!(
            "rootless Podman has no delegated `cpu` cgroup controller (available: {}); delegate it with a systemd `Delegate=cpu` drop-in for user@.service to enforce CPU limits",
            if list.is_empty() { "none".to_string() } else { list.join(", ") })),
        _ => None,
    };
    Ok(Info {
        os: host.get("os").and_then(Value::as_str).unwrap_or("").into(),
        id: host
            .get("hostname")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        graph: v
            .pointer("/store/graphRoot")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        memory_bytes: host
            .get("memTotal")
            .and_then(Value::as_u64)
            .ok_or("Engine probe omitted available VM memory.")?,
        remote: host
            .get("serviceIsRemote")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        operating_system: String::new(),
        cpu_limits_unsupported,
    })
}

pub(super) fn parse_docker_info(v: &Value) -> Result<Info> {
    Ok(Info {
        os: v["OSType"].as_str().unwrap_or("").into(),
        id: v["ID"].as_str().unwrap_or("").into(),
        graph: String::new(),
        memory_bytes: v["MemTotal"]
            .as_u64()
            .ok_or("Engine probe omitted available VM memory.")?,
        remote: false,
        operating_system: v["OperatingSystem"].as_str().unwrap_or("").into(),
        cpu_limits_unsupported: (v.get("CpuCfsQuota").and_then(Value::as_bool) == Some(false))
            .then(|| "the Docker daemon reports no CPU CFS quota support".to_string()),
    })
}

/// Reads the two kernel settings SonarQube's search engine checks. Absent/unreadable → `None`.
#[cfg(any(not(target_os = "macos"), test))]
#[must_use]
pub(super) fn read_limits_at(proc_sys: &Path) -> (Option<u64>, Option<u64>) {
    let read = |name: &str| {
        fs::read_to_string(proc_sys.join(name))
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
    };
    (read("vm/max_map_count"), read("fs/file-max"))
}

#[must_use]
pub(crate) fn limits_low(max_map_count: Option<u64>, file_max: Option<u64>) -> bool {
    max_map_count.is_some_and(|v| v < MIN_MAP_COUNT) || file_max.is_some_and(|v| v < MIN_FILE_MAX)
}

/// The verified machine behind a macOS Podman selection (empty: the default connection).
/// `Ok(None)`: an explicitly selected connection that addresses no local machine, which may serve
/// ordinary engine operations while its VM limits stay unknown and are never changed.
/// The app never creates or starts a machine; a stopped or missing one is reported.
#[cfg(any(target_os = "macos", test))]
fn podman_machine(
    program: &Path,
    connection: &str,
    control: &RunControl,
) -> Result<Option<MachineBinding>> {
    match install::podman_target(program, connection, control)? {
        PodmanTarget::Machine(machine) if machine.running => Ok(Some(machine)),
        PodmanTarget::Machine(machine) => Err(format!("The Podman machine '{0}' behind this connection is not running. Start it yourself (`podman machine start {0}`) and Recheck. OMP Manager does not start machines on macOS.", machine.name)),
        PodmanTarget::Remote => Ok(None),
    }
}

/// Reads the SonarQube kernel settings inside one verified machine. Unreadable → unknown.
#[cfg(any(target_os = "macos", test))]
fn machine_limits(
    program: &Path,
    machine: &str,
    control: &RunControl,
) -> (Option<u64>, Option<u64>) {
    let mut cmd = Command::new(program);
    cmd.args([
        "machine",
        "ssh",
        machine,
        "cat",
        "/proc/sys/vm/max_map_count",
        "/proc/sys/fs/file-max",
    ]);
    match cli_engine::run_bounded(cmd, None, PROBE_TIMEOUT, control) {
        Ok(out) if out.status.success() => {
            let numbers: Vec<u64> = out
                .text()
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            (numbers.first().copied(), numbers.get(1).copied())
        }
        _ => (None, None),
    }
}

#[cfg(any(target_os = "macos", test))]
const REMOTE_LIMITS: &str = "Cannot raise limits on a Podman connection that is not proven to address a local Podman machine. Ask its administrator to set vm.max_map_count>=524288 and fs.file-max>=131072, then Recheck.";

/// Consented raise inside the one machine bound to `connection`; the result is read back only
/// while the same binding (name and creation identity) still holds.
#[cfg(any(target_os = "macos", test))]
fn raise_in_machine(
    program: &Path,
    connection: &str,
    script: &Path,
    control: &RunControl,
) -> Result<()> {
    let machine = podman_machine(program, connection, control)?.ok_or(REMOTE_LIMITS)?;
    let mut cmd = Command::new(program);
    cmd.args([
        "machine",
        "ssh",
        &machine.name,
        "sudo",
        "-n",
        "/bin/sh",
        "-s",
    ]);
    let read = || match podman_machine(program, connection, control) {
        Ok(Some(current)) if current == machine => machine_limits(program, &machine.name, control),
        _ => (None, None),
    };
    raise_with(cmd, script, &read, control)
}

pub(super) fn probe(engine: &CliEngine, control: &RunControl) -> Result<EngineProbe> {
    let podman = matches!(engine.runtime, QualityRuntime::Podman { .. });
    if matches!(
        engine.runtime,
        QualityRuntime::DockerNative | QualityRuntime::DockerDesktop
    ) {
        // The selected context must be this machine's own engine socket, never a TCP/ssh remote.
        let out = engine.success(
            &["context", "inspect"],
            PROBE_TIMEOUT,
            control,
            "Inspect the Docker context",
        )?;
        let contexts: Value = serde_json::from_slice(&out.stdout)
            .map_err(|_| "Invalid Docker context response.".to_string())?;
        let host = contexts
            .pointer("/0/Endpoints/docker/Host")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !host.starts_with("unix://") {
            return Err(format!("The Docker context points at '{host}', not a local engine socket. Select a local context (`docker context use default`); OMP Manager does not use remote engines."));
        }
    }
    let out = engine
        .success(
            &["info", "--format", "{{json .}}"],
            PROBE_TIMEOUT,
            control,
            "Probe selected container engine",
        )
        .map_err(|e| explain_probe_failure(&engine.runtime, e))?;
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| "Invalid or oversized engine info response.".to_string())?;
    let info = if podman {
        parse_podman_info(&v)?
    } else {
        parse_docker_info(&v)?
    };
    if info.os != "linux" {
        return Err("The selected quality runtime must provide a Linux container engine.".into());
    }
    if info.id.is_empty() {
        return Err("The engine did not return a stable daemon identity.".into());
    }
    match &engine.runtime {
        QualityRuntime::Podman { connection }
            if connection.is_empty() && !macos() && info.remote =>
        {
            return Err("Podman is configured as a remote client. Select its connection explicitly instead of the local default.".into());
        }
        QualityRuntime::DockerNative
            if info
                .operating_system
                .to_lowercase()
                .contains("docker desktop") =>
        {
            return Err("The active Docker context is Docker Desktop, not the native Docker Engine. Switch with `docker context use default`.".into());
        }
        QualityRuntime::DockerDesktop
            if !info
                .operating_system
                .to_lowercase()
                .contains("docker desktop") =>
        {
            return Err(
                "The desktop-linux context does not identify the local Docker Desktop daemon."
                    .into(),
            );
        }
        _ => {}
    }
    // One verified machine association supplies both the creation identity and the limit reads.
    #[cfg(target_os = "macos")]
    let (identity, (max_map_count, file_max)) = match &engine.runtime {
        QualityRuntime::Podman { connection } => {
            match podman_machine(&engine.program, connection, control)? {
                Some(machine) => {
                    let limits = machine_limits(&engine.program, &machine.name, control);
                    (machine.created, limits)
                }
                None => (String::new(), (None, None)),
            }
        }
        _ => (String::new(), (None, None)),
    };
    #[cfg(not(target_os = "macos"))]
    let (identity, (max_map_count, file_max)) = (String::new(), host_limits(&engine.runtime));
    let fingerprint = if podman {
        format!("podman:{}:{}:{identity}", info.id, info.graph)
    } else {
        format!("docker:{}", info.id)
    };
    Ok(EngineProbe {
        fingerprint,
        os: info.os,
        memory_bytes: info.memory_bytes,
        max_map_count,
        file_max,
        cpu_limits_unsupported: info.cpu_limits_unsupported,
    })
}

fn explain_probe_failure(runtime: &QualityRuntime, error: String) -> String {
    let lower = error.to_lowercase();
    match runtime {
        QualityRuntime::DockerNative if lower.contains("permission denied") =>
            format!("{error}\nYour user may not use the Docker socket. Add it to the `docker` group (then log in again) or use Podman; OMP Manager never uses sudo for Docker."),
        QualityRuntime::DockerNative if lower.contains("cannot connect") || lower.contains("is the docker daemon running") =>
            format!("{error}\nThe Docker service is not running. Start it (for example `sudo systemctl start docker`); OMP Manager never starts system services."),
        QualityRuntime::Podman { .. } if macos() && (lower.contains("connection") || lower.contains("podman machine")) =>
            format!("{error}\nStart the Podman machine behind this connection yourself (`podman machine start <name>`), or create one first (`podman machine init --now`); OMP Manager does not create or start machines on macOS."),
        _ => error,
    }
}

/// Linux reads its own kernel settings (the engine shares them); a remote Podman connection cannot be
/// inspected from here. (macOS reads them inside the verified machine VM instead.)
#[cfg(not(target_os = "macos"))]
fn host_limits(runtime: &QualityRuntime) -> (Option<u64>, Option<u64>) {
    match runtime {
        QualityRuntime::Podman { connection } if !connection.is_empty() => (None, None),
        _ => read_limits_at(Path::new("/proc/sys")),
    }
}

pub(super) fn ensure_started(engine: &CliEngine, control: &RunControl) -> Result<()> {
    let first = match engine.probe(control) {
        Ok(_) => return Ok(()),
        Err(e) => e,
    };
    match &engine.runtime {
        QualityRuntime::DockerDesktop if macos() => {
            let mut cmd = Command::new("/usr/bin/open");
            cmd.args(["-a", "Docker"]);
            cli_engine::run_bounded(cmd, None, PROBE_TIMEOUT, control)?
                .require_success("Start Docker Desktop")?;
        }
        QualityRuntime::Podman { .. } if macos() => {
            return Err(format!("{first}\nThe selected Podman machine is not reachable. Start it yourself (`podman machine start <name>`); OMP Manager does not create or start machines on macOS."));
        }
        QualityRuntime::Podman { .. } => {
            return Err(format!("{first}\nPodman needs no daemon, so there is nothing to start: fix the problem above (`podman info` must work for your user)."));
        }
        _ => return Err(first),
    }
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut last = first;
    while Instant::now() < deadline {
        if control.cancelled() {
            return Err("Start runtime cancelled.".into());
        }
        match engine.probe(control) {
            Ok(_) => return Ok(()),
            Err(e) => last = e,
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!("Selected runtime did not become ready: {last}"))
}

/// Cached answer to "may `--cpus` be passed to this engine?" (`Some(reason)` = no).
pub(super) fn cpu_limit_problem<'engine>(
    engine: &'engine CliEngine,
    control: &RunControl,
) -> Option<&'engine str> {
    engine
        .cpu_limits
        .get_or_init(|| {
            let out = engine
                .success(
                    &["info", "--format", "{{json .}}"],
                    PROBE_TIMEOUT,
                    control,
                    "Probe CPU limit support",
                )
                .ok()?;
            let v: Value = serde_json::from_slice(&out.stdout).ok()?;
            if matches!(engine.runtime, QualityRuntime::Podman { .. }) {
                parse_podman_info(&v).ok()?.cpu_limits_unsupported
            } else {
                parse_docker_info(&v).ok()?.cpu_limits_unsupported
            }
        })
        .as_deref()
}

/// Prerequisite rows for this platform's runtimes. Never installs, starts or pulls anything.
pub(crate) fn probe_prerequisites(
    config_root: &Path,
    selected: &QualityRuntime,
) -> (Vec<Prerequisite>, QualityOptions) {
    let control = RunControl::silent();
    let connections = super::super::install::podman_connections(&control)
        .map(|list| {
            list.iter()
                .filter_map(|v| v["Name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let options = QualityOptions {
        podman_connections: connections,
        ..QualityOptions::default()
    };
    let podman_installed = podman_program().is_some();
    let mut result = Vec::new();
    for runtime in prerequisite_runtimes(selected, podman_installed)
        .into_iter()
        .flatten()
    {
        let installed = match &runtime {
            QualityRuntime::Podman { .. } => podman_installed,
            QualityRuntime::DockerDesktop => docker_program().is_some(),
            _ => docker_program().is_some(),
        };
        let probe = CliEngine::try_new(runtime.clone(), config_root)
            .and_then(|engine| engine.probe(&control));
        let message = match &probe {
            Err(error) => Some(error.clone()),
            Ok(p) => runtime_notes(&runtime, p),
        };
        result.push(Prerequisite {
            runtime,
            installed,
            ready: probe.is_ok(),
            needs_restart: false,
            message,
        });
    }
    (result, options)
}

/// Podman first: Docker is only discovered and probed when the Podman CLI is missing or Docker is the
/// selected runtime. A stopped or broken Podman is reported as such, never a reason to probe Docker.
fn prerequisite_runtimes(
    selected: &QualityRuntime,
    podman_installed: bool,
) -> [Option<QualityRuntime>; 2] {
    let podman = QualityRuntime::Podman {
        connection: match selected {
            QualityRuntime::Podman { connection } => connection.clone(),
            _ => String::new(),
        },
    };
    let docker_selected = matches!(
        selected,
        QualityRuntime::DockerNative | QualityRuntime::DockerDesktop
    );
    let docker = (!podman_installed || docker_selected).then(|| {
        if macos() {
            QualityRuntime::DockerDesktop
        } else {
            QualityRuntime::DockerNative
        }
    });
    [Some(podman), docker]
}

/// Facts about a *working* engine the user should still see (never errors).
#[must_use]
pub(crate) fn runtime_notes(runtime: &QualityRuntime, probe: &EngineProbe) -> Option<String> {
    let mut notes = Vec::new();
    if limits_low(probe.max_map_count, probe.file_max) {
        notes.push(if macos() {
            "The Podman machine VM's vm.max_map_count/fs.file-max are below what SonarQube needs; use Prepare runtime to raise them inside that verified machine after your approval.".to_string()
        } else {
            format!("vm.max_map_count ({}) or fs.file-max ({}) is below SonarQube's minimum ({MIN_MAP_COUNT}/{MIN_FILE_MAX}); use Prepare runtime to raise it with administrator approval (polkit).",
                probe.max_map_count.map_or("unknown".into(), |v| v.to_string()), probe.file_max.map_or("unknown".into(), |v| v.to_string()))
        });
    } else if macos()
        && matches!(runtime, QualityRuntime::Podman { .. })
        && probe.max_map_count.is_none()
        && probe.file_max.is_none()
    {
        notes.push("This Podman connection is not associated with a local Podman machine (or its kernel settings could not be read), so its VM limits are unknown and OMP Manager will not change them. SonarQube needs vm.max_map_count>=524288 and fs.file-max>=131072.".to_string());
    }
    if let Some(reason) = &probe.cpu_limits_unsupported {
        notes.push(format!(
            "CPU limits are not applied on {}: {reason}.",
            runtime.label()
        ));
    }
    (!notes.is_empty()).then(|| notes.join("\n"))
}

pub(crate) fn pkexec_program() -> Option<PathBuf> {
    let mut dirs = standard_dirs();
    dirs.insert(0, PathBuf::from("/run/wrappers/bin")); // NixOS setuid wrappers
    dirs.iter().map(|d| d.join("pkexec")).find(|p| p.is_file())
}

/// Raises `vm.max_map_count`/`fs.file-max` after explicit consent, never lowering a value. Linux: the
/// fixed script is piped into `pkexec /bin/sh -s` (no script path is ever executed as root, so the
/// user-writable config folder cannot be raced). macOS: inside the one verified Podman machine VM.
pub(crate) fn raise_vm_limits(
    engine: &dyn Engine,
    config_root: &Path,
    control: &RunControl,
) -> Result<()> {
    let script = super::super::install::materialize_vm_limits_script(config_root)?;
    #[cfg(target_os = "macos")]
    if let QualityRuntime::Podman { connection } = engine.runtime() {
        let program = podman_program().ok_or_else(missing_podman)?;
        return raise_in_machine(&program, connection, &script, control);
    }
    let read = || -> (Option<u64>, Option<u64>) {
        engine
            .probe(control)
            .map(|p| (p.max_map_count, p.file_max))
            .unwrap_or((None, None))
    };
    let cmd = match engine.runtime() {
        QualityRuntime::DockerDesktop if macos() => return Err("Docker Desktop does not expose a supported VM sysctl setup API to this app. Follow Docker Desktop's supported Linux VM configuration instructions to set vm.max_map_count>=524288 and fs.file-max>=131072, then Recheck.".into()),
        QualityRuntime::Podman { connection } if !connection.is_empty() => return Err("Cannot raise limits on an unverified remote Podman engine. Ask its administrator to set vm.max_map_count>=524288 and fs.file-max>=131072, then Recheck.".into()),
        QualityRuntime::Podman { .. } | QualityRuntime::DockerNative if !macos() => pkexec_command(pkexec_program())?,
        _ => return Err("This runtime has no Linux VM limits to raise from this platform.".into()),
    };
    raise_with(cmd, &script, &read, control)
}

fn pkexec_command(pkexec: Option<PathBuf>) -> Result<Command> {
    let pkexec = pkexec.ok_or("pkexec (polkit) was not found. Run this as root yourself, then Recheck: sysctl -w vm.max_map_count=524288 fs.file-max=131072")?;
    let mut cmd = Command::new(pkexec);
    cmd.args(["/bin/sh", "-s"]);
    Ok(cmd)
}

/// Runs the privileged helper and requires the limits to hold afterwards.
fn raise_with(
    cmd: Command,
    script: &Path,
    read: &dyn Fn() -> (Option<u64>, Option<u64>),
    control: &RunControl,
) -> Result<()> {
    let out = cli_engine::run_bounded(cmd, Some(script), Duration::from_secs(300), control)?;
    if out.cancelled {
        return Err("Raising the VM limits was cancelled; nothing was changed.".into());
    }
    match out.status.code() {
        Some(126) => return Err("Administrator approval was declined or dismissed, so the VM limits were not changed.".into()),
        Some(127) if !macos() => return Err("pkexec could not ask for administrator approval (no polkit authentication agent is running in this session). Run as root instead: sysctl -w vm.max_map_count=524288 fs.file-max=131072".into()),
        _ => {}
    }
    out.require_success("Raise and verify consented Linux VM limits")?;
    let (map, files) = read();
    if map.unwrap_or(0) < MIN_MAP_COUNT || files.unwrap_or(0) < MIN_FILE_MAX {
        return Err("Linux VM limits could not be verified after the helper. Required: vm.max_map_count>=524288, fs.file-max>=131072. No Community server was started.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;
    use uuid::Uuid;

    // Trimmed from `podman info --format json` of rootless Podman 5.8.9 on this machine.
    const PODMAN_ROOTLESS: &str = r#"{"host":{"os":"linux","hostname":"cachyos-martin","memTotal":133622087680,"cgroupControllers":["memory","pids"],"cgroupManager":"systemd","serviceIsRemote":false,"security":{"rootless":true}},"store":{"graphRoot":"/home/martin/.local/share/containers/storage"}}"#;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omp-native-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn script(path: &Path, text: &str) {
        fs::write(path, text).unwrap();
        fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn parses_rootless_podman_info_and_flags_the_missing_cpu_controller() {
        let info = parse_podman_info(&serde_json::from_str(PODMAN_ROOTLESS).unwrap()).unwrap();
        assert_eq!(
            (info.os.as_str(), info.id.as_str()),
            ("linux", "cachyos-martin")
        );
        assert_eq!(info.graph, "/home/martin/.local/share/containers/storage");
        assert_eq!(info.memory_bytes, 133_622_087_680);
        assert!(!info.remote);
        let reason = info.cpu_limits_unsupported.unwrap();
        assert!(
            reason.contains("memory, pids") && reason.contains("Delegate=cpu"),
            "{reason}"
        );
    }

    #[test]
    fn cpu_limits_stay_enabled_when_the_controller_is_delegated_or_the_engine_is_rootful() {
        let delegated =
            PODMAN_ROOTLESS.replace(r#"["memory","pids"]"#, r#"["cpu","memory","pids"]"#);
        assert_eq!(
            parse_podman_info(&serde_json::from_str(&delegated).unwrap())
                .unwrap()
                .cpu_limits_unsupported,
            None
        );
        let rootful = PODMAN_ROOTLESS.replace(r#""rootless":true"#, r#""rootless":false"#);
        assert_eq!(
            parse_podman_info(&serde_json::from_str(&rootful).unwrap())
                .unwrap()
                .cpu_limits_unsupported,
            None
        );
        // An engine that does not report controllers at all is not assumed to lack them.
        let silent = PODMAN_ROOTLESS.replace(r#""cgroupControllers":["memory","pids"],"#, "");
        assert_eq!(
            parse_podman_info(&serde_json::from_str(&silent).unwrap())
                .unwrap()
                .cpu_limits_unsupported,
            None
        );
        let empty = PODMAN_ROOTLESS.replace(r#"["memory","pids"]"#, "[]");
        assert!(parse_podman_info(&serde_json::from_str(&empty).unwrap())
            .unwrap()
            .cpu_limits_unsupported
            .unwrap()
            .contains("none"));
    }

    #[test]
    fn podman_info_without_memory_is_refused() {
        let v: Value =
            serde_json::from_str(r#"{"host":{"os":"linux","hostname":"h"},"store":{}}"#).unwrap();
        assert!(parse_podman_info(&v).is_err());
        assert!(parse_podman_info(&serde_json::json!({})).is_err());
    }

    #[test]
    fn parses_docker_info_and_cpu_quota_support() {
        let v = serde_json::json!({"ID":"ABCD:1234","OSType":"linux","MemTotal":8589934592u64,"OperatingSystem":"Arch Linux","CpuCfsQuota":true});
        let info = parse_docker_info(&v).unwrap();
        assert_eq!(
            (info.os.as_str(), info.id.as_str(), info.memory_bytes),
            ("linux", "ABCD:1234", 8 << 30)
        );
        assert_eq!(info.cpu_limits_unsupported, None);
        let no_quota =
            serde_json::json!({"ID":"x","OSType":"linux","MemTotal":1u64,"CpuCfsQuota":false});
        assert!(parse_docker_info(&no_quota)
            .unwrap()
            .cpu_limits_unsupported
            .unwrap()
            .contains("CFS"));
        assert!(parse_docker_info(&serde_json::json!({"ID":"x"})).is_err());
    }

    #[test]
    fn limits_are_read_from_proc_sys_and_judged_against_sonars_minimums() {
        let root = scratch();
        fs::create_dir_all(root.join("vm")).unwrap();
        fs::create_dir_all(root.join("fs")).unwrap();
        assert_eq!(read_limits_at(&root), (None, None));
        fs::write(root.join("vm/max_map_count"), "262144\n").unwrap();
        fs::write(root.join("fs/file-max"), "9223372036854775807\n").unwrap();
        let (map, files) = read_limits_at(&root);
        assert_eq!(
            (map, files),
            (Some(262_144), Some(9_223_372_036_854_775_807))
        );
        assert!(limits_low(map, files));
        assert!(!limits_low(Some(524_288), Some(131_072)));
        assert!(
            !limits_low(None, None),
            "unknown limits are not reported as low"
        );
        assert!(
            limits_low(Some(524_287), Some(1 << 30)) && limits_low(Some(1 << 30), Some(131_071))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_kernel_limits_remain_unknown_without_discarding_the_other_limit() {
        let root = scratch();
        fs::create_dir_all(root.join("vm")).unwrap();
        fs::create_dir_all(root.join("fs")).unwrap();
        fs::write(root.join("fs/file-max"), "131072\n").unwrap();
        for invalid in ["-1", "18446744073709551616", "524288 extra", ""] {
            fs::write(root.join("vm/max_map_count"), invalid).unwrap();
            assert_eq!(
                read_limits_at(&root),
                (None, Some(131_072)),
                "malformed map count must not invent a passing value: {invalid:?}"
            );
        }
        fs::write(root.join("vm/max_map_count"), "524288\n").unwrap();
        fs::write(root.join("fs/file-max"), [0xff, 0xfe]).unwrap();
        assert_eq!(read_limits_at(&root), (Some(524_288), None));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn probe_failure_guidance_retains_the_cause_without_prescribing_privilege_escalation() {
        let permission = explain_probe_failure(
            &QualityRuntime::DockerNative,
            "connect /var/run/docker.sock: Permission Denied".into(),
        );
        assert!(permission.starts_with("connect /var/run/docker.sock: Permission Denied"));
        assert!(permission.contains("docker` group"));
        assert!(permission.contains("never uses sudo"));
        for diagnostic in ["Cannot connect to socket", "Is the Docker daemon running?"] {
            let stopped = explain_probe_failure(&QualityRuntime::DockerNative, diagnostic.into());
            assert!(stopped.starts_with(diagnostic));
            assert!(stopped.contains("never starts system services"));
        }
        let unrelated = "engine reported a corrupt storage database";
        assert_eq!(
            explain_probe_failure(&QualityRuntime::DockerNative, unrelated.into()),
            unrelated
        );
        assert_eq!(
            explain_probe_failure(
                &QualityRuntime::Podman {
                    connection: "chosen".into()
                },
                "permission denied on storage".into(),
            ),
            "permission denied on storage"
        );
    }

    #[test]
    fn resolution_is_explicit_per_platform_and_never_falls_back() {
        // Windows-only runtimes are typed errors here, whatever tools happen to be installed.
        assert!(resolve(QualityRuntime::DockerWsl {
            distro: "Ubuntu".into()
        })
        .unwrap_err()
        .contains("only available on Windows"));
        if !macos() {
            assert!(resolve(QualityRuntime::DockerDesktop)
                .unwrap_err()
                .contains("not offered on Linux"));
        }
        assert!(resolve(QualityRuntime::Podman {
            connection: "--evil".into()
        })
        .is_err());
        if let Ok((runtime, _, prefix)) = resolve(QualityRuntime::Podman {
            connection: String::new(),
        }) {
            assert_eq!(
                runtime,
                QualityRuntime::Podman {
                    connection: String::new()
                }
            );
            assert!(
                prefix.is_empty(),
                "an empty connection means the local default, with no --connection flag"
            );
        }
        if let Ok((_, _, prefix)) = resolve(QualityRuntime::Podman {
            connection: "work-box".into(),
        }) {
            assert_eq!(prefix, ["--connection", "work-box"]);
        }
    }

    #[test]
    fn prerequisites_look_up_docker_only_without_podman_or_when_docker_is_selected() {
        let docker = if macos() {
            QualityRuntime::DockerDesktop
        } else {
            QualityRuntime::DockerNative
        };
        let work = QualityRuntime::Podman {
            connection: "work-box".into(),
        };
        let default = QualityRuntime::Podman {
            connection: String::new(),
        };
        // An installed Podman, even stopped or broken, never triggers a Docker lookup.
        assert_eq!(prerequisite_runtimes(&work, true), [Some(work.clone()), None]);
        // A missing Podman CLI falls back to listing Docker after the selected Podman row.
        assert_eq!(
            prerequisite_runtimes(&work, false),
            [Some(work.clone()), Some(docker.clone())]
        );
        // An explicitly selected Docker runtime is always probed, keeping the default Podman row first.
        for selected in [QualityRuntime::DockerDesktop, QualityRuntime::DockerNative] {
            assert_eq!(
                prerequisite_runtimes(&selected, true),
                [Some(default.clone()), Some(docker.clone())]
            );
        }
    }

    #[test]
    fn missing_engine_messages_name_the_nix_install_and_promise_no_install() {
        if macos() {
            let podman = missing_podman();
            assert!(podman.contains("profile add nixpkgs#podman"), "{podman}");
            assert!(podman.contains("podman machine init"), "{podman}");
            assert!(!podman.to_lowercase().contains("brew"), "{podman}");
        } else {
            assert!(missing_podman().contains("nix profile add nixpkgs#podman"));
        }
        for text in [missing_podman(), missing_docker()] {
            assert!(
                text.contains("never installs") || text.contains("never installs software"),
                "{text}"
            );
        }
    }

    /// A fake `podman` CLI with two machines and connection aliases. It records every argv, serves
    /// fixture JSON, and "applies" a consented raise only to the machine it was sent to.
    struct Machines {
        dir: PathBuf,
        program: PathBuf,
        identity: PathBuf,
    }

    const ALIAS: &str = "podman-machine-default-work";

    impl Machines {
        fn new() -> Self {
            let dir = scratch();
            let identity = dir.join("machine-key");
            fs::write(&identity, "fixture key").unwrap();
            std::os::unix::fs::symlink(&identity, dir.join("key-alias")).unwrap();
            fs::write(dir.join("other-key"), "unrelated key").unwrap();
            let program = dir.join("podman");
            script(
                &program,
                &format!(
                    r#"#!/bin/sh
d='{d}'
printf '%s\n' "$*" >> "$d/argv.log"
[ "$1" = --connection ] && shift 2
case "$1 $2" in
"system connection") cat "$d/connections.json" ;;
"machine list") cat "$d/machines.json" ;;
"machine inspect") cat "$d/inspect-$3.json" 2>/dev/null || {{ echo "VM does not exist" >&2; exit 125; }} ;;
"machine ssh")
  m=$3; shift 3
  if [ "$1" = sudo ]; then
    cat > "$d/raised-$m"
    printf '524288\n1048576\n' > "$d/limits-$m"
    if [ -f "$d/replace-on-raise" ]; then sed -i.bak 's/created-quality/created-replacement/' "$d/inspect-$m.json"; fi
    exit 0
  fi
  cat "$d/limits-$m" ;;
"info --format") cat "$d/info.json" ;;
*) echo "unexpected: $*" >&2; exit 2 ;;
esac
"#,
                    d = dir.display()
                ),
            );
            let fixture = Self {
                dir,
                program,
                identity,
            };
            let alias = fixture.dir.join("key-alias");
            let other = fixture.dir.join("other-key");
            fixture.connections(&[
                (
                    "podman-machine-default",
                    "ssh://core@127.0.0.1:50001/run/user/501/podman/podman.sock",
                    &fixture.identity,
                    true,
                ),
                (
                    "podman-machine-default-root",
                    "ssh://root@127.0.0.1:50001/run/podman/podman.sock",
                    &fixture.identity,
                    false,
                ),
                (
                    ALIAS,
                    "ssh://core@127.0.0.1:50002/run/user/501/podman/podman.sock",
                    &alias,
                    false,
                ),
                (
                    "quality-vm-root",
                    "ssh://root@localhost:50002/run/podman/podman.sock",
                    &fixture.identity,
                    false,
                ),
                (
                    "remote-box",
                    "ssh://core@build.example:22/run/user/1000/podman/podman.sock",
                    &fixture.identity,
                    false,
                ),
                (
                    "stale-loopback",
                    "ssh://core@127.0.0.1:50999/run/user/501/podman/podman.sock",
                    &fixture.identity,
                    false,
                ),
                (
                    "wrong-key",
                    "ssh://core@127.0.0.1:50002/run/user/501/podman/podman.sock",
                    &other,
                    false,
                ),
                (
                    "wrong-user",
                    "ssh://admin@127.0.0.1:50002/run/user/501/podman/podman.sock",
                    &fixture.identity,
                    false,
                ),
            ]);
            fixture.machine("podman-machine-default", 50001, "running");
            fixture.machine("quality-vm", 50002, "running");
            fixture.list(&["podman-machine-default", "quality-vm"]);
            for name in ["podman-machine-default", "quality-vm"] {
                fs::write(fixture.dir.join(format!("limits-{name}")), "65530\n65536\n").unwrap();
            }
            fs::write(
                fixture.dir.join("info.json"),
                PODMAN_ROOTLESS.replace(r#""serviceIsRemote":false"#, r#""serviceIsRemote":true"#),
            )
            .unwrap();
            fixture
        }
        fn connections(&self, entries: &[(&str, &str, &PathBuf, bool)]) {
            let list: Vec<Value> = entries
                .iter()
                .map(|(name, uri, identity, default)| {
                    serde_json::json!({"Name": name, "URI": uri, "Identity": identity, "IsMachine": true, "Default": default, "ReadWrite": true})
                })
                .collect();
            fs::write(
                self.dir.join("connections.json"),
                Value::from(list).to_string(),
            )
            .unwrap();
        }
        fn machine(&self, name: &str, port: u64, state: &str) {
            let created = if name == "quality-vm" {
                "created-quality".to_string()
            } else {
                format!("created-{name}")
            };
            let inspect = serde_json::json!([{"Name": name, "Created": created, "State": state, "Rootful": false,
                "SSHConfig": {"IdentityPath": self.identity, "Port": port, "RemoteUsername": "core"}}]);
            fs::write(
                self.dir.join(format!("inspect-{name}.json")),
                inspect.to_string(),
            )
            .unwrap();
        }
        fn list(&self, names: &[&str]) {
            let list: Vec<Value> = names
                .iter()
                .map(|name| serde_json::json!({"Name": name, "Default": *name == "podman-machine-default", "Running": true}))
                .collect();
            fs::write(
                self.dir.join("machines.json"),
                Value::from(list).to_string(),
            )
            .unwrap();
        }
        fn target(&self, connection: &str) -> Result<PodmanTarget> {
            install::podman_target(&self.program, connection, &RunControl::silent())
        }
        fn argv(&self) -> String {
            fs::read_to_string(self.dir.join("argv.log")).unwrap_or_default()
        }
        fn raise_script(&self) -> PathBuf {
            let path = self.dir.join("raise.sh");
            fs::write(&path, "# fixed consented helper\n").unwrap();
            path
        }
    }

    impl Drop for Machines {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn bound(name: &str, created: &str) -> PodmanTarget {
        PodmanTarget::Machine(MachineBinding {
            name: name.into(),
            created: created.into(),
            running: true,
        })
    }

    #[test]
    fn connection_alias_binds_by_endpoint_user_and_identity_never_by_name() {
        let fixture = Machines::new();
        // The alias's name points at the default machine; its endpoint (and a symlinked key) is the other one.
        assert_eq!(
            fixture.target(ALIAS).unwrap(),
            bound("quality-vm", "created-quality")
        );
        assert_eq!(
            fixture.target("quality-vm-root").unwrap(),
            bound("quality-vm", "created-quality")
        );
        assert_eq!(
            fixture.target("").unwrap(),
            bound("podman-machine-default", "created-podman-machine-default")
        );
        assert_eq!(
            fixture.target("podman-machine-default-root").unwrap(),
            bound("podman-machine-default", "created-podman-machine-default")
        );
        for remote in ["remote-box", "stale-loopback", "wrong-key", "wrong-user"] {
            assert_eq!(
                fixture.target(remote).unwrap(),
                PodmanTarget::Remote,
                "{remote}"
            );
        }
        let missing = fixture
            .target("podman-machine-default-missing")
            .unwrap_err();
        assert!(missing.contains("is not configured"), "{missing}");
        assert!(fixture.target("--connection").is_err());
    }

    #[test]
    fn consented_raise_reaches_only_the_bound_machine() {
        let fixture = Machines::new();
        let control = RunControl::silent();
        raise_in_machine(&fixture.program, ALIAS, &fixture.raise_script(), &control).unwrap();
        assert_eq!(
            fs::read_to_string(fixture.dir.join("raised-quality-vm")).unwrap(),
            "# fixed consented helper\n",
            "the fixed script travels on stdin to the bound machine"
        );
        assert!(!fixture.dir.join("raised-podman-machine-default").exists());
        let argv = fixture.argv();
        assert!(
            argv.contains("machine ssh quality-vm sudo -n /bin/sh -s"),
            "{argv}"
        );
        assert!(
            !argv.contains("machine ssh podman-machine-default"),
            "{argv}"
        );
        assert_eq!(
            machine_limits(&fixture.program, "podman-machine-default", &control),
            (Some(65_530), Some(65_536)),
            "the unrelated running default machine keeps its limits"
        );
        assert_eq!(
            machine_limits(&fixture.program, "quality-vm", &control),
            (Some(524_288), Some(1_048_576))
        );
    }

    #[test]
    fn remote_connection_serves_engine_operations_without_vm_authority() {
        let fixture = Machines::new();
        let control = RunControl::silent();
        assert_eq!(
            podman_machine(&fixture.program, "remote-box", &control).unwrap(),
            None
        );
        assert_eq!(
            raise_in_machine(
                &fixture.program,
                "remote-box",
                &fixture.raise_script(),
                &control
            )
            .unwrap_err(),
            REMOTE_LIMITS
        );
        assert!(
            !fixture.argv().contains("machine ssh"),
            "{}",
            fixture.argv()
        );
    }

    #[test]
    fn default_stopped_and_ambiguous_associations_fail_actionably() {
        let fixture = Machines::new();
        let control = RunControl::silent();
        fixture.machine("quality-vm", 50002, "stopped");
        assert_eq!(
            fixture.target(ALIAS).unwrap(),
            PodmanTarget::Machine(MachineBinding {
                name: "quality-vm".into(),
                created: "created-quality".into(),
                running: false
            })
        );
        let stopped = podman_machine(&fixture.program, ALIAS, &control).unwrap_err();
        assert!(
            stopped.contains("podman machine start quality-vm"),
            "{stopped}"
        );
        assert!(
            raise_in_machine(&fixture.program, ALIAS, &fixture.raise_script(), &control).is_err()
        );
        assert!(!fixture.dir.join("raised-quality-vm").exists());
        fixture.machine("quality-vm", 50002, "running");

        fixture.machine("clone-vm", 50002, "running");
        fixture.list(&["podman-machine-default", "quality-vm", "clone-vm"]);
        let ambiguous = fixture.target(ALIAS).unwrap_err();
        assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
        fixture.list(&["podman-machine-default", "quality-vm"]);

        let alias = fixture.dir.join("key-alias");
        fixture.connections(&[(
            ALIAS,
            "ssh://core@127.0.0.1:50002/run/user/501/podman/podman.sock",
            &alias,
            false,
        )]);
        let no_default = fixture.target("").unwrap_err();
        assert!(no_default.contains("podman machine init"), "{no_default}");
        fixture.connections(&[(
            "remote-box",
            "ssh://core@build.example:22/run/user/1000/podman/podman.sock",
            &fixture.identity,
            true,
        )]);
        let remote_default = fixture.target("").unwrap_err();
        assert!(
            remote_default.contains("does not address"),
            "{remote_default}"
        );
        assert_eq!(fixture.target("remote-box").unwrap(), PodmanTarget::Remote);
    }

    #[test]
    fn a_machine_replaced_during_the_raise_is_never_reported_as_raised() {
        let fixture = Machines::new();
        fs::write(fixture.dir.join("replace-on-raise"), "").unwrap();
        let error = raise_in_machine(
            &fixture.program,
            ALIAS,
            &fixture.raise_script(),
            &RunControl::silent(),
        )
        .unwrap_err();
        assert!(error.contains("could not be verified"), "{error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_probe_uses_one_verified_machine_association() {
        let fixture = Machines::new();
        let control = RunControl::silent();
        let alias = CliEngine::scripted(
            QualityRuntime::Podman {
                connection: ALIAS.into(),
            },
            fixture.program.clone(),
            &fixture.dir,
        );
        let found = probe(&alias, &control).unwrap();
        assert!(
            found.fingerprint.ends_with(":created-quality"),
            "{}",
            found.fingerprint
        );
        assert_eq!(
            (found.max_map_count, found.file_max),
            (Some(65_530), Some(65_536))
        );
        let argv = fixture.argv();
        assert!(
            argv.contains(&format!("--connection {ALIAS} info")),
            "{argv}"
        );
        assert!(argv.contains("machine ssh quality-vm cat"), "{argv}");
        assert!(
            !argv.contains("machine ssh podman-machine-default"),
            "{argv}"
        );

        let default = CliEngine::scripted(
            QualityRuntime::Podman {
                connection: String::new(),
            },
            fixture.program.clone(),
            &fixture.dir,
        );
        assert!(probe_fingerprint_of(&default).ends_with(":created-podman-machine-default"));

        fs::remove_file(fixture.dir.join("argv.log")).unwrap();
        let remote = CliEngine::scripted(
            QualityRuntime::Podman {
                connection: "remote-box".into(),
            },
            fixture.program.clone(),
            &fixture.dir,
        );
        let found = probe(&remote, &control).unwrap();
        assert!(found.fingerprint.ends_with(':'), "{}", found.fingerprint);
        assert_eq!((found.max_map_count, found.file_max), (None, None));
        assert!(
            !fixture.argv().contains("machine ssh"),
            "{}",
            fixture.argv()
        );
        let notes = runtime_notes(remote.runtime(), &found).unwrap();
        assert!(notes.contains("unknown"), "{notes}");

        let missing = CliEngine::scripted(
            QualityRuntime::Podman {
                connection: "deleted-alias".into(),
            },
            fixture.program.clone(),
            &fixture.dir,
        );
        assert!(probe(&missing, &control)
            .unwrap_err()
            .contains("is not configured"));
    }

    #[cfg(target_os = "macos")]
    fn probe_fingerprint_of(engine: &CliEngine) -> String {
        probe(engine, &RunControl::silent()).unwrap().fingerprint
    }

    /// The raise path against a fake `pkexec` that records its argv and stdin and "applies" the change
    /// to a fake `/proc/sys`: proves the script travels on stdin to `/bin/sh -s`, and the result is verified.
    #[test]
    fn privileged_raise_pipes_the_fixed_script_to_pkexec_sh_and_verifies_the_result() {
        let dir = scratch();
        let proc = dir.join("proc");
        fs::create_dir_all(proc.join("vm")).unwrap();
        fs::create_dir_all(proc.join("fs")).unwrap();
        fs::write(proc.join("vm/max_map_count"), "65530\n").unwrap();
        fs::write(proc.join("fs/file-max"), "1000000\n").unwrap();
        let fake = dir.join("pkexec");
        script(&fake, &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{d}/argv'\ncat > '{d}/stdin'\nprintf 524288 > '{p}/vm/max_map_count'\nexit 0\n",
            d = dir.display(), p = proc.display()));
        let script_file = dir.join("raise.sh");
        fs::write(
            &script_file,
            include_str!("../../../../bridge/code-quality/raise-vm-limits.sh"),
        )
        .unwrap();
        let read = || read_limits_at(&proc);
        assert!(limits_low(read().0, read().1));
        raise_with(
            pkexec_command(Some(fake.clone())).unwrap(),
            &script_file,
            &read,
            &RunControl::silent(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("argv")).unwrap(),
            "/bin/sh\n-s\n"
        );
        let piped = fs::read_to_string(dir.join("stdin")).unwrap();
        assert!(
            piped.contains("never lower") || piped.contains("Never lower"),
            "the fixed helper reached stdin"
        );
        assert_eq!(
            read(),
            (Some(524_288), Some(1_000_000)),
            "an already higher value is retained"
        );
        assert!(!limits_low(read().0, read().1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn privileged_raise_rejects_failed_helpers_and_unverified_outcomes() {
        use std::sync::atomic::AtomicBool;

        let dir = scratch();
        let script_file = dir.join("raise.sh");
        fs::write(&script_file, "exit 0\n").unwrap();
        let never_raised = || (Some(65_530u64), Some(1_000_000u64));
        let checked = AtomicBool::new(false);
        let read = || {
            checked.store(true, Ordering::Relaxed);
            never_raised()
        };
        for code in [126, 127] {
            let fake = dir.join(format!("pkexec-{code}"));
            script(&fake, &format!("#!/bin/sh\ncat >/dev/null\nexit {code}\n"));
            assert!(raise_with(
                pkexec_command(Some(fake)).unwrap(),
                &script_file,
                &read,
                &RunControl::silent()
            )
            .is_err());
            assert!(
                !checked.load(Ordering::Relaxed),
                "failed helper must not reach post-success verification"
            );
        }
        // The helper claims success but the kernel value did not change: never reported as raised.
        let liar = dir.join("pkexec-liar");
        script(&liar, "#!/bin/sh\ncat >/dev/null\nexit 0\n");
        let error = raise_with(
            pkexec_command(Some(liar)).unwrap(),
            &script_file,
            &never_raised,
            &RunControl::silent(),
        )
        .unwrap_err();
        assert!(error.contains("could not be verified"), "{error}");
        // A failing helper (not root) is an error with its diagnostic.
        let failing = dir.join("pkexec-fail");
        script(&failing, "#!/bin/sh\ncat >/dev/null\necho 'Raising SonarQube Linux VM limits requires root.' >&2\nexit 1\n");
        let error = raise_with(
            pkexec_command(Some(failing)).unwrap(),
            &script_file,
            &never_raised,
            &RunControl::silent(),
        )
        .unwrap_err();
        assert!(error.contains("requires root"), "{error}");
        // No pkexec at all: explicit manual instruction, never a silent skip.
        assert!(pkexec_command(None)
            .err()
            .unwrap()
            .contains("sysctl -w vm.max_map_count=524288"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cancelling_the_privileged_helper_changes_nothing() {
        let dir = scratch();
        let fake = dir.join("pkexec");
        script(&fake, "#!/bin/sh\nsleep 30\n");
        let script_file = dir.join("raise.sh");
        fs::write(&script_file, "exit 0\n").unwrap();
        let control = RunControl::silent();
        let cancelling = control.clone();
        let task = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            cancelling.cancel.store(true, Ordering::Relaxed);
        });
        let error = raise_with(
            pkexec_command(Some(fake)).unwrap(),
            &script_file,
            &|| (None, None),
            &control,
        )
        .unwrap_err();
        task.join().unwrap();
        assert!(error.contains("cancelled"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }
}
