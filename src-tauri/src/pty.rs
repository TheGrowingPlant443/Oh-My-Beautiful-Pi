use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::ipc::{Channel, InvokeResponseBody};
use vt100::{Callbacks, Parser, Screen};

use crate::config::ConfigDirectory;
use crate::host_monitor::ProcessIdentity;
use crate::instance::{Definition, InstanceKind};
use crate::manager::BridgeLaunch;

pub const DEFAULT_COLS: u16 = 120;
pub const DEFAULT_ROWS: u16 = 32;
const REPLAY_LIMIT: usize = 256 * 1024;
type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

#[derive(Default)]
struct TerminalReplies {
    bytes: Vec<u8>,
}
impl Callbacks for TerminalReplies {
    fn unhandled_csi(
        &mut self,
        screen: &mut Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        action: char,
    ) {
        if action == 'c' && i1.is_none() && i2.is_none() && params == [&[0u16][..]] {
            // Match xterm's VT100 with Advanced Video response; do not advertise unsupported extensions.
            self.bytes.extend_from_slice(b"\x1b[?1;2c");
            return;
        }
        if action != 'n'
            || i2.is_some()
            || !matches!(i1, None | Some(b'?'))
            || params != [&[6u16][..]]
        {
            return;
        }
        let (row, col) = screen.cursor_position();
        let private = if i1 == Some(b'?') { "?" } else { "" };
        let _ = write!(self.bytes, "\x1b[{private}{};{}R", row + 1, col + 1);
    }
}

struct Output {
    bytes: VecDeque<u8>,
    channel: Option<Channel<InvokeResponseBody>>,
    parser: Parser<TerminalReplies>,
}
impl Output {
    fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
            channel: None,
            parser: Parser::new_with_callbacks(
                DEFAULT_ROWS,
                DEFAULT_COLS,
                0,
                TerminalReplies::default(),
            ),
        }
    }
}
struct Shared {
    output: Mutex<Output>,
    last_output: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalScreen {
    pub text: String,
    pub cols: u16,
    pub rows: u16,
    pub cursor_row: u16,
    pub cursor_col: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedConfiguration {
    config_files: Vec<PathBuf>,
    model: Option<String>,
    local: bool,
    slot_manifest: Value,
    #[serde(default)]
    thinking_level: Option<String>,
}

pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    writer: Writer,
    child: Box<dyn Child + Send + Sync>,
    shared: Arc<Shared>,
    pub cols: u16,
    pub rows: u16,
    exit: Option<u32>,
    /// An observed root exit does not release the PID until its session is retired.
    reaped: bool,
    /// Session retirement is separate from observing/reaping the root's exit.
    retired: bool,
    /// PID plus creation time captured while the PTY owns the child handle; read-only attribution for the host monitor.
    root: Option<ProcessIdentity>,
    _config_directory: Option<ConfigDirectory>,
}

impl Pty {
    pub fn spawn(definition: &Definition, bridge: &BridgeLaunch) -> Result<Self, String> {
        let app_root = bridge
            .extension_path
            .parent()
            .ok_or("invalid bridge directory")?;
        let sdk = bridge.sdk_dir.as_ref().ok_or("Native configuration setups require the matching OMP SDK. Configure OMP_SDK_DIR before starting this session.")?;
        let cli = sdk.join("src/cli.ts");
        if !cli.is_file() {
            return Err(
                "OMP compatibility: the installed SDK has no exported native source CLI".into(),
            );
        }
        let directory = ConfigDirectory::create(app_root)?;
        let input = &definition.input;
        let prepared: PreparedConfiguration = serde_json::from_value(crate::config::native_request(
            app_root, &bridge.home_dir, serde_json::json!({
                "action":"prepare_session","directory":directory.0,"configRoot":app_root,
                "cwd":input.project_path,"profile":input.profile,"configFiles":input.configs,
                "configDefault":input.config_default,"configSelection":input.config_selection,
                "model":input.model,"sessionPath":definition.session_path.as_ref().filter(|path| path.is_file()),
                "helper":definition.helper.is_some()
            }),
        )?).map_err(|error| format!("Invalid native configuration preparation: {error}"))?;
        let local_enabled = prepared.local && Self::has_local_assets(definition, bridge);
        // Source entry and extension SDK imports must share one native settings/capability registry.
        let mut cmd = CommandBuilder::new(crate::toolchain::bun_program());
        cmd.arg(cli);
        cmd.env_remove("PI_COMPILED");
        cmd.env_remove("OMSP_COMPILED");
        cmd.cwd(&definition.input.project_path);
        Self::add_session_args(&mut cmd, definition, &prepared)?;
        Self::add_extensions(&mut cmd, definition, bridge, app_root, local_enabled)?;
        Self::add_bridge_env(&mut cmd, definition, bridge)?;
        cmd.env(
            "OMP_MANAGER_CONFIG_SLOT_MANIFEST",
            serde_json::to_string(&prepared.slot_manifest).map_err(|error| error.to_string())?,
        );
        let mut process = Self::start(cmd)?;
        process._config_directory = Some(directory);
        Ok(process)
    }
    fn has_local_assets(definition: &Definition, bridge: &BridgeLaunch) -> bool {
        // Read-only helpers keep their restricted tool surface, regardless of their model.
        definition.helper.is_none()
            && [
                "AGENTS.md",
                "RULES.md",
                "SKILLS.md",
                "agent-instructions",
                "rules",
                "skills",
                "tools",
                "extensions",
            ]
            .iter()
            .any(|name| bridge.local_ai_setup_dir.join(name).exists())
    }
    fn add_session_args(
        cmd: &mut CommandBuilder,
        definition: &Definition,
        prepared: &PreparedConfiguration,
    ) -> Result<(), String> {
        let input = &definition.input;
        cmd.args(["--cwd", &input.project_path]);
        cmd.args([
            "--profile",
            if input.profile.is_empty() {
                "default"
            } else {
                &input.profile
            },
        ]);
        for config in &prepared.config_files {
            cmd.arg("--config");
            cmd.arg(config);
        }
        if let Some(model) = &prepared.model {
            cmd.args(["--model", model]);
        }
        if let Some(thinking) = &prepared.thinking_level {
            cmd.args(["--thinking", thinking]);
        }
        // OMP creates sessions lazily: a path reported before the first message has no file to resume.
        if let Some(path) = definition.session_path.as_ref().filter(|p| p.is_file()) {
            cmd.arg("--resume");
            cmd.arg(path);
        }
        if let Some(path) = &input.agent_file {
            cmd.arg("--append-system-prompt");
            cmd.arg(path);
        }
        // A helper agent (Code diff / Git tree) has no built-in tools at all; its tools are the bridge's repo_inspect and code_quality_report.
        if definition.helper.is_some() {
            cmd.arg("--no-tools");
        }
        Ok(())
    }
    fn add_extensions(
        cmd: &mut CommandBuilder,
        definition: &Definition,
        bridge: &BridgeLaunch,
        app_root: &Path,
        local_enabled: bool,
    ) -> Result<(), String> {
        cmd.env("OMP_MANAGER_LOCAL_AI_SETUP_DIR", &bridge.local_ai_setup_dir);
        cmd.env(
            "OMP_MANAGER_LOCAL_AI_SETUP_MODE",
            if local_enabled { "local" } else { "ordinary" },
        );
        cmd.arg("--extension");
        cmd.arg(app_root.join("local-ai-guard.ts"));
        if local_enabled {
            cmd.arg("--extension");
            cmd.arg(&bridge.local_ai_setup_dir);
            Self::add_scoped_packages(cmd, &bridge.local_ai_setup_dir, "Local AI models")?;
        }
        cmd.arg("--extension");
        cmd.arg(&bridge.extension_path);
        cmd.arg("--omp-manager-bridge");
        cmd.env_remove("OMP_MANAGER_PRIVATE_SETUP_DIR");
        cmd.env_remove("OMP_MANAGER_PRIVATE_SETUP_ROLE");
        let private_setup = match definition.kind {
            InstanceKind::Manager => Some((&bridge.manager_setup_dir, "manager", "Manager")),
            InstanceKind::Architect => {
                Some((&bridge.architect_setup_dir, "architect", "Architect"))
            }
            _ => None,
        };
        let Some((root, role, label)) = private_setup else {
            return Ok(());
        };
        cmd.arg("--extension");
        cmd.arg(root);
        cmd.env("OMP_MANAGER_PRIVATE_SETUP_DIR", root);
        cmd.env("OMP_MANAGER_PRIVATE_SETUP_ROLE", role);
        // Private packages remain confined to their coordinator's directory.
        Self::add_scoped_packages(cmd, root, label)
    }
    fn add_scoped_packages(
        cmd: &mut CommandBuilder,
        root: &Path,
        label: &str,
    ) -> Result<(), String> {
        for package in crate::setup::scoped_plugin_paths(root, label)? {
            cmd.arg("--extension");
            cmd.arg(package);
        }
        Ok(())
    }
    fn add_bridge_env(
        cmd: &mut CommandBuilder,
        definition: &Definition,
        bridge: &BridgeLaunch,
    ) -> Result<(), String> {
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("WT_SESSION", &definition.id);
        cmd.env("TERM_SESSION_ID", &definition.id);
        if let Some(root) = bridge.extension_path.parent() {
            cmd.env("OMP_MANAGER_CONFIG_ROOT", root);
        }
        cmd.env(
            "OMP_MANAGER_CONFIG_FILES",
            serde_json::to_string(&definition.input.configs)
                .map_err(|error| format!("Configuration paths cannot be encoded: {error}"))?,
        );
        cmd.env(
            "OMP_MANAGER_CONFIG_DEFAULT",
            definition
                .input
                .config_default
                .as_deref()
                .unwrap_or_else(|| Path::new("")),
        );
        cmd.env(
            "OMP_MANAGER_CONFIG_SELECTION",
            definition
                .input
                .config_selection
                .as_deref()
                .unwrap_or_else(|| Path::new("")),
        );
        cmd.env(
            "OMP_MANAGER_CONFIG_USE_DEFAULT",
            if definition
                .input
                .use_global_config
                .unwrap_or(definition.input.profile.is_empty())
            {
                "1"
            } else {
                "0"
            },
        );
        if let Some(sdk) = &bridge.sdk_dir {
            cmd.env("OMP_MANAGER_SDK_DIR", sdk);
        }
        cmd.env("OMP_MANAGER_BRIDGE_ENDPOINT", &bridge.endpoint);
        cmd.env("OMP_MANAGER_BRIDGE_TOKEN", &bridge.token);
        cmd.env("OMP_MANAGER_BRIDGE_INSTANCE_ID", &bridge.instance_id);
        cmd.env(
            "OMP_MANAGER_BRIDGE_GENERATION",
            bridge.generation.to_string(),
        );
        cmd.env(
            "OMP_MANAGER_BRIDGE_ROLE",
            if bridge.role == InstanceKind::Manager {
                "manager"
            } else {
                "instance"
            },
        );
        if definition.kind == InstanceKind::Architect {
            cmd.env("OMP_MANAGER_ARCHITECT_DIR", &bridge.architect_dir);
        }
        if let Some(link) = definition.helper.as_ref() {
            cmd.env("OMP_MANAGER_HELPER_REPO", &link.repo);
        } else {
            cmd.env("OMP_MANAGER_BROWSER_REQUIRED", "1");
            // Both are required for command capture; without the SDK the bridge reports the feature as unavailable.
            if let Some(sdk) = &bridge.sdk_dir {
                cmd.env("OMP_MANAGER_TERMINAL_DIR", &bridge.terminal_dir);
                cmd.env("OMP_MANAGER_SDK_DIR", sdk);
            }
        }
        if definition.plan_target.is_some() {
            cmd.env("OMP_MANAGER_PLAN_SESSION", "1");
        }
        cmd.env("PI_BROWSER_RELAY", "0");
        cmd.env("PI_BROWSER_TERN", "0");
        cmd.env("PI_BROWSER_CMUX", "0");
        cmd.env("OMSP_BROWSER_RELAY", "0");
        cmd.env("OMSP_BROWSER_TERN", "0");
        cmd.env("OMSP_BROWSER_CMUX", "0");
        Ok(())
    }
    /// The user's own shell: no OMP arguments, no bridge credentials, nothing from the manager environment.
    pub fn spawn_shell(cwd: &str) -> Result<Self, String> {
        let mut cmd = CommandBuilder::new_default_prog();
        cmd.cwd(cwd);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("OMP_MANAGER_") {
                cmd.env_remove(name);
            }
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        Self::start(cmd)
    }
    fn start(cmd: CommandBuilder) -> Result<Self, String> {
        let pair = portable_pty::native_pty_system()
            .openpty(PtySize {
                rows: DEFAULT_ROWS,
                cols: DEFAULT_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        drop(pair.slave);
        let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let root = child
            .process_id()
            .and_then(crate::host_monitor::capture_identity);
        let writer: Writer = Arc::new(Mutex::new(
            pair.master.take_writer().map_err(|e| e.to_string())?,
        ));
        let shared = Arc::new(Shared {
            output: Mutex::new(Output::new()),
            last_output: AtomicU64::new(0),
        });
        let pump = shared.clone();
        let reply_writer = writer.clone();
        std::thread::spawn(move || drain(reader, pump, reply_writer));
        Ok(Self {
            master: pair.master,
            writer,
            child,
            shared,
            cols: DEFAULT_COLS,
            rows: DEFAULT_ROWS,
            exit: None,
            reaped: false,
            retired: false,
            root,
            _config_directory: None,
        })
    }
    pub fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }
    /// Creation identity of the launched root, captured at launch; `None` when it could not be read.
    pub fn root_identity(&self) -> Option<ProcessIdentity> {
        self.root
    }
    /// Immediate termination for a shell the user closed; OMP uses `stop` for a graceful Ctrl-C first.
    pub fn kill(&mut self) -> Result<(), String> {
        #[cfg(not(unix))]
        if self.poll()?.is_some() {
            return Ok(());
        }
        if self.reaped && self.retired {
            return Ok(());
        }
        // Keep the leader unreaped if retirement fails, so a later attempt still
        // owns the session identity rather than a potentially recycled PID.
        self.kill_process_group()?;
        self.child.kill().map_err(|e| e.to_string())?;
        self.exit = Some(self.child.wait().map_err(|e| e.to_string())?.exit_code());
        self.reaped = true;
        Ok(())
    }
    /// portable-pty creates a session. Shell job-control groups must also be retired before the leader is reaped.
    fn kill_process_group(&mut self) -> Result<(), String> {
        if self.retired {
            return Ok(());
        }
        #[cfg(unix)]
        {
            let pid = self.child.process_id().ok_or("PTY root identity is unavailable")?;
            crate::process_tree::kill_session(pid)?;
        }
        self.retired = true;
        Ok(())
    }
    #[cfg(unix)]
    fn root_exit_unreaped(&self) -> Result<Option<u32>, String> {
        let pid = self.child.process_id().ok_or("PTY root identity is unavailable")?;
        // portable-pty owns this direct child and no other code waits on it.
        // WNOWAIT leaves even an exited leader reserved until every session member
        // is retired; unlike try_wait, it cannot open a PID/session-reuse window.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: info is a writable siginfo_t and pid names our owned child.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                if info.si_signo != libc::SIGCHLD {
                    return Ok(None);
                }
                // Match portable-pty: ordinary exit status, or 1 for signal death.
                #[cfg(target_os = "macos")]
                let status = info.si_status;
                #[cfg(target_os = "linux")]
                // SAFETY: waitid populated the SIGCHLD variant of siginfo_t.
                let status = unsafe { info.si_status() };
                return Ok(Some(if info.si_code == libc::CLD_EXITED {
                    status as u32
                } else {
                    1
                }));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("Inspect PTY root exit: {error}"));
            }
        }
    }
    #[must_use]
    pub fn last_output(&self) -> u64 {
        self.shared.last_output.load(Ordering::Relaxed)
    }
    pub fn poll(&mut self) -> Result<Option<u32>, String> {
        #[cfg(unix)]
        {
            self.poll_unix(crate::process_tree::try_kill_session)
        }
        #[cfg(not(unix))]
        {
            if self.exit.is_none() {
                self.exit = self.child.try_wait().map_err(|e| e.to_string())?
                    .map(|status| status.exit_code());
            }
            if self.exit.is_some() {
                self.reaped = true;
                self.retired = true;
                self._config_directory = None;
            }
            Ok(self.exit)
        }
    }
    #[cfg(unix)]
    fn poll_unix(
        &mut self,
        retire: impl FnOnce(u32) -> Result<bool, String>,
    ) -> Result<Option<u32>, String> {
        if self.exit.is_none() {
            self.exit = self.root_exit_unreaped()?;
        }
        if self.exit.is_some() && !self.reaped {
            if !self.retired {
                let pid = self.child.process_id().ok_or("PTY root identity is unavailable")?;
                // Routine UI polling never waits for an unsignalable or stuck member.
                // Keep the zombie leader reserved and let later polls verify retirement;
                // explicit kill/stop/drop retain the bounded retirement wait.
                self.retired = retire(pid)?;
            }
            if self.retired {
                self.exit = Some(self.child.wait().map_err(|e| e.to_string())?.exit_code());
                self.reaped = true;
                self._config_directory = None;
            }
        }
        Ok(self.exit)
    }
    /// Root exit is observable even while session retirement is pending or failed.
    pub fn exit_code(&self) -> Option<u32> {
        self.exit
    }
    pub fn write(&mut self, data: &str) -> Result<(), String> {
        if self.poll()?.is_some() {
            return Err("instance not running".into());
        }
        let mut writer = self.writer.lock().map_err(|e| e.to_string())?;
        writer
            .write_all(data.as_bytes())
            .and_then(|_| writer.flush())
            .map_err(|e| e.to_string())
    }
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        if !(2..=500).contains(&cols) || !(2..=200).contains(&rows) {
            return Err("invalid terminal dimensions".into());
        }
        if self.cols == cols && self.rows == rows {
            return Ok(());
        }
        self.master
            .resize(PtySize {
                cols,
                rows,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;
        self.shared
            .output
            .lock()
            .map_err(|e| e.to_string())?
            .parser
            .screen_mut()
            .set_size(rows, cols);
        self.cols = cols;
        self.rows = rows;
        Ok(())
    }
    pub fn screen(&self) -> Result<TerminalScreen, String> {
        let output = self.shared.output.lock().map_err(|e| e.to_string())?;
        let screen = output.parser.screen();
        let (rows, cols) = screen.size();
        let (cursor_row, cursor_col) = screen.cursor_position();
        Ok(TerminalScreen {
            text: screen.contents(),
            cols,
            rows,
            cursor_row,
            cursor_col,
        })
    }
    pub fn attach(&self, channel: Channel<InvokeResponseBody>) -> Result<(), String> {
        let mut output = self.shared.output.lock().map_err(|e| e.to_string())?;
        channel
            .send(InvokeResponseBody::Raw(
                output.bytes.iter().copied().collect(),
            ))
            .map_err(|e| e.to_string())?;
        output.channel = Some(channel);
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), String> {
        if self.poll()?.is_some() {
            return self.kill();
        }
        let _ = self.write("\x03");
        std::thread::sleep(Duration::from_millis(300));
        let _ = self.write("\x03");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.poll()?.is_some() {
                return self.kill();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.kill_process_group()?;
        self.child.kill().map_err(|e| e.to_string())?;
        self.exit = Some(self.child.wait().map_err(|e| e.to_string())?.exit_code());
        self.reaped = true;
        self._config_directory = None;
        Ok(())
    }
}
impl Drop for Pty {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_process_group();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn drain(mut reader: Box<dyn Read + Send>, shared: Arc<Shared>, writer: Writer) {
    let mut buffer = [0u8; 8192];
    let mut replies = Vec::new();
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        {
            let mut output = match shared.output.lock() {
                Ok(output) => output,
                Err(e) => {
                    eprintln!("terminal output lock: {e}");
                    break;
                }
            };
            output.parser.process(&buffer[..read]);
            std::mem::swap(&mut replies, &mut output.parser.callbacks_mut().bytes);
            output.bytes.extend(&buffer[..read]);
            let excess = output.bytes.len().saturating_sub(REPLAY_LIMIT);
            output.bytes.drain(..excess);
            shared
                .last_output
                .store(crate::session::now_ms(), Ordering::Relaxed);
            if let Some(channel) = &output.channel {
                if channel
                    .send(InvokeResponseBody::Raw(buffer[..read].to_vec()))
                    .is_err()
                {
                    output.channel = None;
                }
            }
        }
        if !replies.is_empty() {
            if let Ok(mut writer) = writer.lock() {
                let _ = writer.write_all(&replies).and_then(|_| writer.flush());
            }
            replies.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_configuration_capsule_is_private_and_removed_on_drop() {
        let root =
            std::env::temp_dir().join(format!("omp-config-capsule-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path;
        {
            let directory = ConfigDirectory::create(&root).unwrap();
            path = directory.0.clone();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            std::fs::write(path.join("config.yml"), "{}\n").unwrap();
        }
        assert!(!path.exists());
        assert!(root.exists(), "cleanup is limited to the owned capsule");
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn screen_and_cursor_queries_survive_split_input() {
        let mut parser = vt100::Parser::new_with_callbacks(24, 80, 0, TerminalReplies::default());
        parser.process("café".as_bytes());
        parser.process(b"\x1b[");
        parser.process(b"6n");
        assert_eq!(parser.screen().contents(), "café");
        assert_eq!(parser.callbacks().bytes, b"\x1b[1;5R");
        parser.callbacks_mut().bytes.clear();
        parser.process(b"\x1b[?6n");
        assert_eq!(parser.callbacks().bytes, b"\x1b[?1;5R");
        parser.screen_mut().set_size(40, 100);
        assert_eq!(parser.screen().size(), (40, 100));
    }

    #[test]
    fn primary_device_attributes_are_answered_once_across_every_chunk_boundary() {
        for query in [b"\x1b[c".as_slice(), b"\x1b[0c"] {
            for split in 0..=query.len() {
                let mut output = Output::new();
                output.parser.process(&query[..split]);
                output.parser.process(&query[split..]);
                assert_eq!(output.parser.callbacks().bytes, b"\x1b[?1;2c");
                output.parser.callbacks_mut().bytes.clear();
                output
                    .parser
                    .process(b"text\x1b[>c\x1b[?c\x1b[1c\x1b[0;0c\x1b[0:1c");
                assert!(output.parser.callbacks().bytes.is_empty());
                assert_eq!(output.parser.screen().contents(), "text");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn fish_starts_and_accepts_input_without_an_attached_terminal() {
        let Some(fish) = crate::toolchain::find_program("fish") else {
            eprintln!("skipped: fish is not installed");
            return;
        };
        let mut cmd = CommandBuilder::new(fish);
        cmd.args(["--no-config", "--interactive"]);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        // The prompt marker is emitted only after fish completes its startup terminal queries.
        cmd.args([
            "--init-command",
            "function fish_prompt; printf 'FISH_READY> '; end",
        ]);
        let mut shell = Pty::start(cmd).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = shell.screen().unwrap().text;
            assert!(!text.contains("Primary Device Attribute"), "{text}");
            if text.contains("FISH_READY>") {
                break;
            }
            assert!(Instant::now() < deadline, "fish startup stalled: {text:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
        shell.write("printf '\\n%s\\n' INPUT_PRESERVED\n").unwrap();
        loop {
            let text = shell.screen().unwrap().text;
            assert!(!text.contains("Primary Device Attribute"), "{text}");
            if text.lines().any(|line| line == "INPUT_PRESERVED") {
                break;
            }
            assert!(Instant::now() < deadline, "fish lost shell input: {text:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
        shell.kill().unwrap();
    }

    /// Everything the shell started that stayed in its process group ends with it (the Windows job's Unix counterpart).
    #[cfg(unix)]
    #[test]
    fn killing_a_shell_ends_the_background_processes_it_started() {
        let folder = std::env::temp_dir();
        let mut shell = Pty::spawn_shell(folder.to_str().unwrap()).unwrap();
        shell
            .write("sh -c 'sleep 600 & echo CHILD_PID=$!; wait'\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let child: libc::pid_t = loop {
            let text = shell.screen().unwrap().text;
            let found = text
                .lines()
                .filter_map(|line| line.rsplit_once("CHILD_PID=").map(|(_, pid)| pid))
                .find_map(|pid| pid.trim().parse().ok());
            if let Some(pid) = found {
                break pid;
            }
            assert!(
                Instant::now() < deadline,
                "the shell never printed the child pid: {text:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(
            // SAFETY: signal 0 probes the numeric child PID without sending a signal or accessing Rust memory.
            unsafe { libc::kill(child, 0) },
            0,
            "the background process is alive before the kill"
        );
        shell.kill().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        // The orphaned sleep is reparented and reaped by init/subreaper; wait for it to disappear.
        // SAFETY: signal 0 accepts a numeric PID and only probes existence; it does not access Rust memory.
        while unsafe { libc::kill(child, 0) } == 0 && !is_zombie(child) {
            assert!(
                Instant::now() < deadline,
                "the background process survived the shell's kill"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[cfg(unix)]
    #[test]
    fn natural_root_exit_retires_background_children_before_reaping() {
        struct Cleanup(crate::host_monitor::ProcessIdentity);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if crate::host_monitor::capture_identity(self.0.pid) == Some(self.0) {
                    // SAFETY: this is the fixture's observed child, with its creation
                    // identity rechecked; cleanup is also needed if an assertion fails.
                    unsafe { libc::kill(self.0.pid as libc::pid_t, libc::SIGKILL); }
                }
            }
        }
        for action in ["poll", "kill", "stop", "drop"] {
            let mut cmd = CommandBuilder::new("/bin/sh");
            // HUP is ignored by the child so kernel terminal hangup alone cannot
            // make this regression pass. The root waits until its PID was captured.
            cmd.args([
                "-c",
                "trap '' HUP; sleep 600 & printf 'CHILD_PID=%s\\n' \"$!\"; read answer; exit 7",
            ]);
            let mut shell = Pty::start(cmd).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let child: u32 = loop {
                let text = shell.screen().unwrap().text;
                if let Some(pid) = text.lines()
                    .filter_map(|line| line.strip_prefix("CHILD_PID="))
                    .find_map(|pid| pid.trim().parse().ok())
                {
                    break pid;
                }
                assert!(Instant::now() < deadline, "no background child: {text:?}");
                std::thread::sleep(Duration::from_millis(20));
            };
            let child_identity = crate::host_monitor::capture_identity(child).unwrap();
            let _cleanup = Cleanup(child_identity);
            shell.write("exit now\n").unwrap();
            // Observe the natural exit without calling poll (which must retire the
            // session). The zombie still reserves the leader PID/session identity.
            while shell.root_exit_unreaped().unwrap().is_none() {
                assert!(Instant::now() < deadline, "the root did not exit naturally");
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(crate::host_monitor::capture_identity(child), Some(child_identity));
            assert!(!is_zombie(child as libc::pid_t), "hangup killed the fixture early");
            match action {
                "poll" => {
                    assert_eq!(shell.poll().unwrap(), Some(7));
                    assert_eq!(shell.poll().unwrap(), Some(7));
                    shell.kill().unwrap();
                }
                "kill" => shell.kill().unwrap(),
                "stop" => shell.stop().unwrap(),
                "drop" => {}
                _ => unreachable!(),
            }
            drop(shell);
            let deadline = Instant::now() + Duration::from_secs(5);
            while crate::host_monitor::capture_identity(child) == Some(child_identity)
                && !is_zombie(child as libc::pid_t)
            {
                assert!(Instant::now() < deadline, "{action} left the background child alive");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn pending_or_failed_retirement_preserves_exit_and_unreaped_identity() {
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "exit 23"]);
        let mut shell = Pty::start(cmd).unwrap();
        let root = shell.process_id().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while shell.root_exit_unreaped().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the fixture root never exited");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Inject pending/failed membership checks around a real, naturally exited
        // child. Each poll gets exactly one pass, never a bounded wait/retry loop.
        let mut attempts = 0;
        for expected in 1..=10 {
            assert_eq!(shell.poll_unix(|pid| {
                assert_eq!(pid, root);
                attempts += 1;
                Ok(false)
            }).unwrap(), Some(23));
            assert_eq!(attempts, expected);
            assert!(!shell.retired && !shell.reaped);
            assert_eq!(shell.root_exit_unreaped().unwrap(), Some(23), "pending retirement reaped its leader");
        }
        assert!(shell.poll_unix(|_| Err("membership unavailable".into())).is_err());
        assert_eq!(shell.exit_code(), Some(23), "failed cleanup must not hide root exit");
        assert!(!shell.retired && !shell.reaped);
        assert_eq!(shell.root_exit_unreaped().unwrap(), Some(23));
        // A later real pass verifies the empty session and only then reaps.
        assert_eq!(shell.poll().unwrap(), Some(23));
        assert!(shell.retired && shell.reaped);
        assert_eq!(shell.poll().unwrap(), Some(23));
        shell.kill().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn is_zombie(pid: libc::pid_t) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit(')')
                .next()
                .is_some_and(|rest| rest.trim_start().starts_with('Z'))
        })
    }

    #[cfg(target_os = "macos")]
    fn is_zombie(pid: libc::pid_t) -> bool {
        // SAFETY: proc_pidinfo receives a full writable proc_bsdinfo; it is read only after a complete result.
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        read == size && unsafe { info.assume_init() }.pbi_status == 5
    }
}
