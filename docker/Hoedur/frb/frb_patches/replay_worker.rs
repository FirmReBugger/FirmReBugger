use std::{
    ffi::CString,
    fs::File,
    io::{BufRead, Read, Seek, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::runner::ReplaySession;

const PREFIX: &str = "FRB_WORKER\t";

extern "C" {
    fn firmrebugger_reset_session() -> std::os::raw::c_int;
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

fn archive_path(request: &Value) -> Result<PathBuf> {
    request
        .get("metadata")
        .and_then(|metadata| metadata.get("corpus_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .context("Hoedur worker request has no corpus_path metadata")
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
        let stdout = memory_file("frb-hoedur-stdout")?;
        let stderr = memory_file("frb-hoedur-stderr")?;
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

    fn finish(mut self) -> (String, String) {
        unsafe {
            libc::fflush(std::ptr::null_mut());
            libc::dup2(self.saved_stdout, libc::STDOUT_FILENO);
            libc::dup2(self.saved_stderr, libc::STDERR_FILENO);
            libc::close(self.saved_stdout);
            libc::close(self.saved_stderr);
        }
        (
            read_capture(&mut self.stdout),
            read_capture(&mut self.stderr),
        )
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

fn replay_one(session: &mut ReplaySession, seed_path: &str) -> Result<Value> {
    let capture = Capture::new()?;
    let reset_status = unsafe { firmrebugger_reset_session() };
    if reset_status != 0 {
        let (stdout, stderr) = capture.finish();
        return Ok(json!({
            "op": "result", "status": "reset_error", "restart_worker": true,
            "returncode": 2, "stdout": stdout, "stderr": stderr,
            "error": format!("FirmReBugger reset failed with status {reset_status}")
        }));
    }
    session.reset()?;
    let started = std::time::Instant::now();
    let result = session.replay(PathBuf::from(seed_path).as_path());
    let elapsed = started.elapsed().as_secs_f64();
    let (stdout, stderr) = capture.finish();
    match result {
        Ok(()) => Ok(json!({
            "op": "result", "status": "ok", "returncode": 0,
            "elapsed": elapsed, "stdout": stdout, "stderr": stderr
        })),
        Err(error) => Ok(json!({
            "op": "result", "status": "error", "restart_worker": true,
            "returncode": 1, "elapsed": elapsed, "stdout": stdout,
            "stderr": stderr, "error": format!("{error:#}")
        })),
    }
}

fn set_stdin_blocking() {
    // Hoedur/QEMU changes the file-status flags on fd 0 while creating and
    // restoring an emulator. The pipe's flags are shared with this protocol
    // reader, so restore blocking mode before *every* request read.
    unsafe {
        let flags = libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
}

pub fn run() -> Result<()> {
    let mut session: Option<ReplaySession> = None;
    let stdin = std::io::stdin();
    let mut protocol = stdin.lock();
    loop {
        set_stdin_blocking();
        let mut line = String::new();
        if protocol.read_line(&mut line)? == 0 {
            break;
        }
        if !line.starts_with(PREFIX) {
            continue;
        }
        let request: Value = serde_json::from_str(&line[PREFIX.len()..])?;
        apply_env(&request);
        let operation = request.get("op").and_then(Value::as_str).unwrap_or("");
        let response = match operation {
            "start" => json!({"op": "ready", "status": "ok"}),
            "reset" => {
                if session.is_none() {
                    let capture = Capture::new()?;
                    let created = ReplaySession::create(archive_path(&request)?);
                    let (stdout, stderr) = capture.finish();
                    match created {
                        Ok(created) => {
                            session = Some(created);
                            json!({"op": "result", "status": "ok", "stdout": stdout, "stderr": stderr})
                        }
                        Err(error) => {
                            json!({"op": "result", "status": "reset_error", "error": format!("{error:#}"), "stdout": stdout, "stderr": stderr})
                        }
                    }
                } else {
                    json!({"op": "result", "status": "ok"})
                }
            }
            "replay" => {
                let seed_path = request
                    .get("seed_path")
                    .and_then(Value::as_str)
                    .context("Hoedur replay request has no seed_path")?;
                let session = session
                    .as_mut()
                    .context("Hoedur replay requested before successful reset")?;
                replay_one(session, seed_path)?
            }
            "shutdown" => {
                send(json!({"op": "result", "status": "ok"}))?;
                return Ok(());
            }
            _ => {
                json!({"op": "error", "status": "error", "error": format!("unknown worker operation: {operation}")})
            }
        };
        send(response)?;
    }
    Ok(())
}
