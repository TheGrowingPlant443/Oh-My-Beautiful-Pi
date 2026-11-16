//! Unix listener/process inventory. Native NUL-delimited argv (Darwin KERN_PROCARGS2
//! or Linux procfs) preserves argument identity without interpreting shell display text.
use super::live::{Listener, Row};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;

pub(crate) fn tcp_listeners() -> Result<Vec<Listener>, String> {
    let inventory = crate::host_monitor::native::collect(&AtomicBool::new(false))?;
    Ok(inventory
        .tcp
        .into_iter()
        .filter(|row| row.tcp_state == Some(2))
        .filter_map(|row| {
            Some(Listener {
                address: row.local.address.parse().ok()?,
                port: row.local.port,
                pid: row.pid,
            })
        })
        .collect())
}
pub(crate) fn creation_time(pid: u32) -> Option<u64> {
    crate::process_tree::process_creation_time(pid)
}
pub(crate) fn parent_map() -> Result<HashMap<u32, u32>, String> {
    let inventory = crate::host_monitor::native::collect(&AtomicBool::new(false))?;
    Ok(inventory
        .processes
        .into_iter()
        .map(|p| (p.pid, p.parent_pid))
        .collect())
}
pub(crate) fn in_tree(parents: &HashMap<u32, u32>, root: u32, root_created: u64, pid: u32) -> bool {
    if creation_time(root) != Some(root_created) {
        return false;
    }
    let Some(mut child_created) = creation_time(pid) else {
        return false;
    };
    let mut current = pid;
    for _ in 0..64 {
        if current == root {
            return child_created == root_created;
        }
        let Some(&parent) = parents.get(&current) else {
            return false;
        };
        let Some(parent_created) = creation_time(parent) else {
            return false;
        };
        if parent_created > child_created {
            return false;
        }
        current = parent;
        child_created = parent_created;
    }
    false
}

#[cfg(target_os = "linux")]
pub(super) fn query_processes() -> Result<Vec<Row>, String> {
    use std::io::Read;
    let mut rows = Vec::new();
    for entry in std::fs::read_dir("/proc")
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(exe) = std::fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("python") && name != "node" {
            continue;
        }
        let Some(created) = creation_time(pid) else {
            continue;
        };
        let Ok(file) = std::fs::File::open(entry.path().join("cmdline")) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file.take(32769).read_to_end(&mut bytes).is_err() || bytes.len() > 32768 {
            continue;
        }
        let Some(argv) = nul_arguments(&bytes) else {
            continue;
        };
        if creation_time(pid) != Some(created) {
            continue;
        }
        rows.push(Row {
            pid,
            created,
            exe: exe.to_string_lossy().into_owned(),
            argv,
        });
    }
    Ok(rows)
}

/// `/proc` already supplies argument boundaries. Remove only its final terminator,
/// never empty arguments or literal quotes/backslashes inside an argument.
#[cfg(any(target_os = "linux", test))]
fn nul_arguments(bytes: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(bytes.strip_suffix(&[0])?).ok()?;
    Some(text.split('\0').map(str::to_owned).collect())
}

#[cfg(any(target_os = "macos", test))]
const MAX_PROCARGS: usize = 1024 * 1024;

/// Darwin supplies native argc, an executable-path header, padding, then argv and
/// environment strings. Only the first argc arguments belong to the command.
#[cfg(any(target_os = "macos", test))]
fn procargs_arguments(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() > MAX_PROCARGS {
        return None;
    }
    let width = std::mem::size_of::<libc::c_int>();
    let argc = libc::c_int::from_ne_bytes(bytes.get(..width)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok().filter(|&n| n > 0)?;
    let header = bytes.get(width..)?;
    let end = header.iter().position(|&byte| byte == 0)?;
    if end == 0 {
        return None;
    }
    let mut rest = header.get(end + 1..)?;
    let start = rest.iter().position(|&byte| byte != 0)?;
    rest = &rest[start..];
    // Every argument needs a terminator; reject impossible argc before allocating.
    if argc > rest.len() {
        return None;
    }
    let mut argv = Vec::new();
    for _ in 0..argc {
        let end = rest.iter().position(|&byte| byte == 0)?;
        argv.push(std::str::from_utf8(&rest[..end]).ok()?.to_owned());
        rest = &rest[end + 1..];
    }
    Some(argv)
}

#[cfg(target_os = "macos")]
fn argument_buffer() -> Option<Vec<u8>> {
    let mut maximum: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&maximum);
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: the output is a native c_int with its exact writable size.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            (&mut maximum as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length != std::mem::size_of_val(&maximum) {
        return None;
    }
    let maximum = usize::try_from(maximum).ok()?;
    if maximum == 0 || maximum > MAX_PROCARGS {
        return None;
    }
    Some(vec![0u8; maximum])
}

#[cfg(target_os = "macos")]
fn process_arguments(pid: libc::pid_t, bytes: &mut [u8]) -> Option<Vec<String>> {
    let mut length = bytes.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: sysctl receives the bounded writable buffer and its size, and returns
    // the actual byte count. A failed/truncated query is never parsed.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length > bytes.len() {
        return None;
    }
    procargs_arguments(&bytes[..length])
}

#[cfg(target_os = "macos")]
pub(super) fn query_processes() -> Result<Vec<Row>, String> {
    // SAFETY: a null buffer queries the count; the second call writes at most the
    // supplied byte size to a suitably aligned pid_t buffer.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count < 0 || count as usize > MAX_PROCARGS / std::mem::size_of::<libc::pid_t>() - 256 {
        return Err("macOS process inspection failed".into());
    }
    let mut pids = vec![0 as libc::pid_t; count as usize + 256];
    let count = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr().cast(),
            (pids.len() * std::mem::size_of::<libc::pid_t>()) as i32,
        )
    };
    if count < 0 || count as usize >= pids.len() {
        return Err("macOS process inspection failed".into());
    }
    let mut arguments = argument_buffer().ok_or("macOS process argument limit is unavailable or exceeds 1 MiB")?;
    let mut rows = Vec::new();
    for &pid in &pids[..count as usize] {
        if pid <= 0 {
            continue;
        }
        let Some(created) = creation_time(pid as u32) else {
            continue;
        };
        let mut buffer = [0u8; 4096];
        // SAFETY: buffer is a valid writable byte array; proc_pidpath writes at most its length.
        let length = unsafe {
            libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32)
        };
        if length <= 0 || length as usize >= buffer.len() {
            continue;
        }
        let Ok(exe) = std::str::from_utf8(&buffer[..length as usize]) else {
            continue;
        };
        let name = std::path::Path::new(exe)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !name.starts_with("python") && name != "Python" && name != "node" {
            continue;
        }
        let Some(argv) = process_arguments(pid, &mut arguments) else {
            continue;
        };
        if creation_time(pid as u32) != Some(created) {
            continue;
        }
        rows.push(Row {
            pid: pid as u32,
            created,
            exe: exe.to_owned(),
            argv,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn native_argument_records_preserve_boundaries_and_ignore_environment() {
        let args = ["/tmp/Cognee café/venv/bin/python", "-m", "uvicorn", "", "a\"b\\c", ""];
        let mut nul = args.join("\0").into_bytes();
        nul.push(0);
        assert_eq!(nul_arguments(&nul).unwrap(), args);
        assert!(nul_arguments(b"unterminated").is_none());
        assert!(nul_arguments(b"\xff\0").is_none());

        let mut darwin = (args.len() as libc::c_int).to_ne_bytes().to_vec();
        darwin.extend_from_slice(b"/Library/Frameworks/Python.framework/Python\0\0\0");
        darwin.extend_from_slice(&nul);
        darwin.extend_from_slice(b"SECRET=not an argument\0");
        assert_eq!(procargs_arguments(&darwin).unwrap(), args);
        assert!(procargs_arguments(&[0; 3]).is_none());
        assert!(procargs_arguments(&vec![0; MAX_PROCARGS + 1]).is_none());
        for argc in [-1 as libc::c_int, 0, libc::c_int::MAX] {
            let mut malformed = darwin.clone();
            malformed[..std::mem::size_of::<libc::c_int>()]
                .copy_from_slice(&argc.to_ne_bytes());
            assert!(procargs_arguments(&malformed).is_none());
        }
        let mut truncated = (2 as libc::c_int).to_ne_bytes().to_vec();
        truncated.extend_from_slice(b"/python\0\0/python\0missing terminator");
        assert!(procargs_arguments(&truncated).is_none());
        let mut invalid = (1 as libc::c_int).to_ne_bytes().to_vec();
        invalid.extend_from_slice(b"/python\0\0\xff\0");
        assert!(procargs_arguments(&invalid).is_none());
    }

    #[test]
    fn backend_argv_preserves_unicode_venv_and_rejects_empty_or_combined_options() {
        use super::super::components::Backend;
        use super::super::live::verify_backends;
        let root = std::env::temp_dir()
            .join(format!("omp Cognee café \"quoted\"-{}", uuid::Uuid::new_v4()));
        let bin = root.join("venv/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let python = bin.join("python");
        let args = [
            python.to_str().unwrap(), "-m", "uvicorn", "cognee.api.client:app",
            "--host", "127.0.0.1", "--port", "8000",
        ];
        let mut row = Row {
            pid: 42,
            created: 100,
            exe: "/Library/Frameworks/Python.framework/Python".into(),
            argv: args.into_iter().map(str::to_owned).collect(),
        };
        let listeners = [Listener {
            address: "127.0.0.1".parse().unwrap(),
            port: 8000,
            pid: row.pid,
        }];
        let verify = |row: &Row| verify_backends(std::slice::from_ref(row), &listeners, &python, &|_| Some(100));
        assert_eq!(verify(&row), vec![Backend {
            pid: row.pid, port: 8000, address: listeners[0].address,
        }]);
        assert!(verify_backends(std::slice::from_ref(&row), &listeners, &python, &|_| Some(200)).is_empty());
        row.argv.insert(4, String::new());
        assert!(verify(&row).is_empty());
        row.argv.remove(4);
        row.argv.splice(6..8, ["--port 8000".into()]);
        assert!(verify(&row).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_inventory_reads_real_argv_without_shell_tokenization() {
        let python = crate::toolchain::find_program("python3")
            .expect("the native test environment supplies Python 3");
        let args = ["-c", "import time; time.sleep(30)", "", "café with spaces", "literal\"quote\\slash", ""];
        let mut child = Command::new(&python).args(args).spawn().unwrap();
        // Always retire the fixture before asserting, including inventory errors.
        let rows = query_processes();
        let _ = child.kill();
        let _ = child.wait();
        let row = rows.unwrap().into_iter().find(|row| row.pid == child.id())
            .expect("the real Python process appears in the native inventory");
        assert_eq!(row.argv[0], python.to_str().unwrap());
        assert_eq!(&row.argv[1..], &args);
    }

    #[test]
    fn a_loopback_listener_is_attributed_to_the_process_that_bound_it() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let found = tcp_listeners().unwrap();
        assert!(
            found.contains(&Listener {
                address: "127.0.0.1".parse().unwrap(),
                port,
                pid: std::process::id()
            }),
            "{found:?}"
        );
    }

    #[test]
    fn only_descendants_of_the_launched_root_are_in_its_tree() {
        let mut root = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & wait"])
            .spawn()
            .unwrap();
        let created = creation_time(root.id()).expect("root identity");
        let deadline = Instant::now() + Duration::from_secs(10);
        let (parents, grandchild) = loop {
            let parents = parent_map().unwrap();
            if let Some((&pid, _)) = parents.iter().find(|(_, &parent)| parent == root.id()) {
                break (parents, pid);
            }
            assert!(
                Instant::now() < deadline,
                "the shell never started its background child"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let owned = in_tree(&parents, root.id(), created, grandchild);
        let unrelated = in_tree(&parents, root.id(), created, std::process::id());
        let stale_identity = in_tree(&parents, root.id(), created + 1, grandchild);
        // std::process::Child does not own the shell's background child, so kill its observed PID directly.
        // SAFETY: kill accepts any PID; this is the test's observed child and SIGKILL is a valid signal.
        unsafe {
            libc::kill(grandchild as i32, libc::SIGKILL);
        }
        root.kill().unwrap();
        root.wait().unwrap();
        assert!(owned, "a grandchild belongs to the owned tree");
        assert!(
            !unrelated,
            "this test process is not a descendant of its own child"
        );
        assert!(
            !stale_identity,
            "a root whose creation identity differs must not own anything"
        );
    }

    #[test]
    fn a_backend_is_recognized_by_the_real_bin_directory_of_the_installed_venv() {
        use super::super::live::launched_from_venv;
        let root = std::env::temp_dir().join(format!("omp-venv-{}", std::process::id()));
        let store = root.join("store/bin");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("python3.13"), "").unwrap();
        // A Nix-style environment: the folder's venv is a link to the real directory, and the process reports the versioned name.
        std::os::unix::fs::symlink(root.join("store"), root.join("venv")).unwrap();
        let configured = root.join("venv/bin/python");
        let reported = store.join("python3.13");
        assert!(launched_from_venv(
            reported.to_str().unwrap(),
            "",
            &configured
        ));
        assert!(launched_from_venv(
            configured.to_str().unwrap(),
            "",
            &configured
        ));
        // The shared base interpreter and unrelated environments are not this venv.
        assert!(!launched_from_venv(
            "/usr/bin/python3",
            "/usr/bin/python3",
            &configured
        ));
        assert!(!launched_from_venv(
            root.join("other/bin/python3.13").to_str().unwrap(),
            "",
            &configured
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Opt-in end-to-end proof with the real installed frontend, Node.js and a running Cognee backend:
    /// `OMP_COGNEE_NATIVE=1 OMP_KNOWLEDGE_COGNEE_HOME=<cognee folder> cargo test real_frontend`.
    /// It starts only its own Next.js server (no browser is opened) and checks that shutdown frees the port.
    #[test]
    fn real_frontend_starts_on_loopback_and_is_retired_on_shutdown() {
        use super::super::components::{inspect_components, FRONTEND_PORT};
        use super::super::live::{discover_backends, CogneeUi, Hooks};
        use crate::knowledge::dto::CogneeOpenState;
        let (Ok("1"), Some(folder)) = (
            std::env::var("OMP_COGNEE_NATIVE").as_deref(),
            std::env::var_os("OMP_KNOWLEDGE_COGNEE_HOME"),
        ) else {
            return;
        };
        let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
        let components = inspect_components(std::path::Path::new(&folder), &home, None)
            .expect("installed frontend, Node.js and Next native binding");
        let opened = std::sync::Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let seen = opened.clone();
        let ui = CogneeUi::new();
        ui.set_hooks(Hooks {
            frontend_port: FRONTEND_PORT,
            startup_timeout: Duration::from_secs(120),
            discover: Box::new(discover_backends),
            opener: Box::new(move |url| {
                seen.lock().push(url.to_string());
                Ok(())
            }),
        });
        let result = ui.open(&components);
        assert_eq!(result.state, CogneeOpenState::Opened, "{result:?}");
        assert_eq!(
            *opened.lock(),
            vec![format!("http://localhost:{FRONTEND_PORT}")]
        );
        let root = ui.owned_pid().expect("the frontend is owned");
        let owners: Vec<u32> = tcp_listeners()
            .unwrap()
            .into_iter()
            .filter(|l| l.port == FRONTEND_PORT && l.address.is_loopback())
            .map(|l| l.pid)
            .collect();
        assert!(!owners.is_empty(), "the frontend listens on loopback");
        let parents = parent_map().unwrap();
        let created = creation_time(root).unwrap();
        assert!(
            owners
                .iter()
                .all(|&pid| in_tree(&parents, root, created, pid)),
            "every listener belongs to the owned tree: {owners:?} root {root}"
        );
        ui.shutdown();
        let deadline = Instant::now() + Duration::from_secs(15);
        while tcp_listeners()
            .unwrap()
            .iter()
            .any(|l| l.port == FRONTEND_PORT)
            || creation_time(root).is_some()
        {
            assert!(Instant::now() < deadline, "the frontend survived shutdown");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
