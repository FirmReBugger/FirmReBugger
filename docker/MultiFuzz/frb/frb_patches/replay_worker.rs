use std::{
    ffi::CString,
    fs::File,
    io::{Read, Seek, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use icicle_cortexm::{config::FirmwareConfig, CortexmTarget};
use icicle_fuzzing::{FuzzConfig, FuzzTarget};
use icicle_vm::Vm;
use serde_json::{json, Value};

use crate::{
    config::EnabledFeatures, debugging::replay_input, input::MultiStream, setup_vm, Config,
};

const PREFIX: &str = "FRB_WORKER\t";

type Target = CortexmTarget<icicle_cortexm::mmio::FuzzwareMmioHandler<MultiStream>>;

struct Session {
    target: Option<Target>,
    vm: Option<Vm>,
    config_path: PathBuf,
}

struct Capture {
    stdout: File,
    stderr: File,
    saved_stdout: i32,
    saved_stderr: i32,
}

impl Capture {
    fn new() -> Result<Self> {
        std::io::stdout().flush().ok();
        std::io::stderr().flush().ok();

        let stdout = memory_file("frb-multifuzz-stdout")?;
        let stderr = memory_file("frb-multifuzz-stderr")?;
        let saved_stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
        let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
        if saved_stdout < 0 || saved_stderr < 0 {
            anyhow::bail!("failed to duplicate worker output descriptors");
        }
        if unsafe { libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO) } < 0
        {
            anyhow::bail!("failed to redirect worker output");
        }

        Ok(Self {
            stdout,
            stderr,
            saved_stdout,
            saved_stderr,
        })
    }

    fn finish(mut self) -> Result<(String, String)> {
        unsafe {
            libc::fflush(std::ptr::null_mut());
            libc::dup2(self.saved_stdout, libc::STDOUT_FILENO);
            libc::dup2(self.saved_stderr, libc::STDERR_FILENO);
            libc::close(self.saved_stdout);
            libc::close(self.saved_stderr);
        }
        Ok((
            read_capture(&mut self.stdout),
            read_capture(&mut self.stderr),
        ))
    }
}

fn memory_file(name: &str) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_capture(file: &mut File) -> String {
    file.rewind().ok();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn send(value: Value) -> Result<()> {
    println!("{PREFIX}{}", serde_json::to_string(&value)?);
    std::io::stdout().flush()?;
    Ok(())
}

fn apply_env(request: &Value) {
    if let Some(env) = request.get("env").and_then(Value::as_object) {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                std::env::set_var(key, value);
            }
        }
    }
}

fn config_path(request: &Value) -> Result<PathBuf> {
    if let Some(path) = request.get("config_path").and_then(Value::as_str) {
        return Ok(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var("TARGET_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var("FRB_REPLAY_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    anyhow::bail!("MultiFuzz worker requires TARGET_CONFIG or config_path")
}

fn create_session(
    request: &Value,
    fuzzer_config: &FuzzConfig,
    interrupt_flag: &Arc<AtomicBool>,
) -> Result<Session> {
    let config_path = config_path(request)?.canonicalize()?;
    let firmware = FirmwareConfig::from_path(&config_path)
        .with_context(|| format!("failed to load MultiFuzz config {}", config_path.display()))?;
    let workdir = std::env::var_os("WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./workdir"));
    let mut config = Config {
        fuzzer: fuzzer_config.clone(),
        workdir,
        firmware,
        interrupt_flag: interrupt_flag.clone(),
    };
    let features = EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;
    Ok(Session {
        target: Some(target),
        vm: Some(vm),
        config_path,
    })
}

fn replay_child(session: &mut Session, seed_path: &str, timeout: f64) -> Result<Value> {
    let mut stdout = memory_file("frb-multifuzz-replay-stdout")?;
    let mut stderr = memory_file("frb-multifuzz-replay-stderr")?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("failed to fork MultiFuzz replay child");
    }
    if pid == 0 {
        unsafe {
            libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO);
            libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO);
        }
        let target = session.target.take().expect("replay target missing");
        let vm = session.vm.take().expect("replay VM missing");
        let result = replay_input(target, vm, seed_path);
        if let Err(error) = result {
            eprintln!("{error:#}");
            unsafe { libc::_exit(1) }
        }
        std::io::stdout().flush().ok();
        std::io::stderr().flush().ok();
        unsafe {
            libc::fflush(std::ptr::null_mut());
            libc::_exit(0)
        }
    }

    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(timeout.max(0.1));
    let mut status = 0;
    let mut timed_out = false;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            break;
        }
        if waited < 0 {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    let stdout_text = read_capture(&mut stdout);
    let stderr_text = read_capture(&mut stderr);
    let elapsed = started.elapsed().as_secs_f64();

    if timed_out {
        return Ok(json!({
            "op": "result",
            "status": "timeout",
            "timed_out": true,
            "returncode": Value::Null,
            "elapsed": elapsed,
            "stdout": stdout_text,
            "stderr": stderr_text,
        }));
    }

    let returncode = if unsafe { libc::WIFEXITED(status) } {
        unsafe { libc::WEXITSTATUS(status) }
    } else if unsafe { libc::WIFSIGNALED(status) } {
        128 + unsafe { libc::WTERMSIG(status) }
    } else {
        1
    };
    Ok(json!({
        "op": "result",
        "status": if returncode == 0 { "ok" } else { "crash" },
        "returncode": returncode,
        // The replay ran in a disposable fork. Even a target panic or signal
        // cannot mutate the clean configured VM retained by the parent.
        "restart_worker": false,
        "elapsed": elapsed,
        "stdout": stdout_text,
        "stderr": stderr_text,
    }))
}

pub fn run(fuzzer_config: FuzzConfig, interrupt_flag: Arc<AtomicBool>) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
    let mut session: Option<Session> = None;

    for line in std::io::stdin().lines() {
        let line = line?;
        if !line.starts_with(PREFIX) {
            continue;
        }
        let request: Value = serde_json::from_str(&line[PREFIX.len()..])?;
        let operation = request.get("op").and_then(Value::as_str).unwrap_or("");
        apply_env(&request);
        let result = match operation {
            "start" => json!({"op": "ready", "status": "ok"}),
            "reset" => {
                let setup = if session.is_none() {
                    let capture = Capture::new()?;
                    let created = create_session(&request, &fuzzer_config, &interrupt_flag);
                    let (stdout, stderr) = capture.finish()?;
                    match created {
                        Ok(new_session) => {
                            session = Some(new_session);
                            json!({"op": "result", "status": "ok", "stdout": stdout, "stderr": stderr})
                        }
                        Err(error) => {
                            json!({"op": "result", "status": "reset_error", "error": format!("{error:#}"), "stdout": stdout, "stderr": stderr})
                        }
                    }
                } else {
                    json!({"op": "result", "status": "ok"})
                };
                setup
            }
            "replay" => {
                let seed_path = request
                    .get("seed_path")
                    .and_then(Value::as_str)
                    .context("MultiFuzz replay request has no seed_path")?;
                let timeout = request
                    .get("timeout")
                    .and_then(Value::as_f64)
                    .unwrap_or(10.0);
                let session = session
                    .as_mut()
                    .context("MultiFuzz replay requested before successful reset")?;
                replay_child(session, seed_path, timeout)?
            }
            "shutdown" => {
                send(json!({"op": "result", "status": "ok"}))?;
                return Ok(());
            }
            _ => {
                json!({"op": "error", "status": "error", "error": format!("unknown worker operation: {operation}")})
            }
        };
        send(result)?;
    }
    Ok(())
}
