//! Shared helpers: formatting, PATH lookup, and running external tools —
//! captured, streamed with live progress, and (on Linux) with root rights.

use crate::module::RunContext;
use crate::parse::text::clean_progress_line;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- formatting

/// Format a byte count as a human-readable string (e.g. `14.2 GB`).
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// Format a duration in seconds as `Nd Nh Nm` (used for uptime).
pub fn human_duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    parts.push(format!("{mins}m"));
    parts.join(" ")
}

/// Compact relative time: "just now", "14m ago", "3h ago", "2d ago".
pub fn ago(secs: u64) -> String {
    match secs {
        0..=59 => "just now".to_string(),
        60..=3_599 => format!("{}m ago", secs / 60),
        3_600..=86_399 => format!("{}h ago", secs / 3_600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// Seconds since the Unix epoch, now.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `"s"` when `n != 1`, for "3 updates" / "1 update".
pub fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Exit status as people read it. Large or negative codes are HRESULTs
/// (winget, WUA-backed tools), so show those in hex.
pub fn exit_label(code: Option<i32>) -> String {
    match code {
        Some(c) if !(0..=0xFFFF).contains(&c) => format!("exit 0x{:08X}", c as u32),
        Some(c) => format!("exit {c}"),
        None => "killed by a signal".to_string(),
    }
}

// --------------------------------------------------------------- PATH lookup

/// Find an executable on PATH without spawning `where`/`which` (from a GUI app
/// on Windows that would flash a console window, and it costs a process).
pub fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        Vec::new()
    };

    for dir in std::env::split_paths(&path) {
        let bare = dir.join(program);
        if (!cfg!(windows) || bare.extension().is_some()) && is_present(&bare) {
            return Some(bare);
        }
        for ext in &exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if is_present(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// `symlink_metadata`, not `metadata`: on Windows, winget is an App Execution
/// Alias (a reparse point) that `metadata()` can't open.
fn is_present(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| !m.is_dir())
        .unwrap_or(false)
}

pub fn command_exists(program: &str) -> bool {
    find_in_path(program).is_some()
}

// ---------------------------------------------------------- running commands

/// A `Command` with sane defaults for a GUI host: no stdin (so a tool that
/// prompts gets EOF instead of hanging), and on Windows no console window
/// flashing up for every child process.
pub fn cmd(program: impl AsRef<OsStr>) -> Command {
    let mut c = Command::new(program);
    c.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

/// What a finished command produced.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    /// stdout and stderr joined, trimmed.
    pub fn combined(&self) -> String {
        let (o, e) = (self.stdout.trim(), self.stderr.trim());
        match (o.is_empty(), e.is_empty()) {
            (_, true) => o.to_string(),
            (true, false) => e.to_string(),
            (false, false) => format!("{o}\n{e}"),
        }
    }
}

fn program_name(c: &Command) -> String {
    Path::new(c.get_program())
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| c.get_program().to_string_lossy().into_owned())
}

/// Run to completion and capture output. Errors only if the program can't
/// start; a non-zero exit comes back in `code` for the caller to interpret
/// (plenty of tools use exit codes as data — `dnf check-update` returns 100).
pub fn capture(mut command: Command) -> Result<CmdOutput, String> {
    let name = program_name(&command);
    let out = command
        .output()
        .map_err(|e| format!("could not run `{name}`: {e}"))?;
    Ok(CmdOutput {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Run, capture, and treat a non-zero exit as an error.
pub fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let mut c = cmd(program);
    c.args(args);
    let out = capture(c)?;
    if out.success() {
        Ok(out.combined())
    } else {
        Err(format!(
            "`{program}` failed ({}): {}",
            exit_label(out.code),
            out.combined()
        ))
    }
}

/// Run a command, forwarding each finished output line to `ctx.log` as it
/// arrives. Returns the cleaned transcript (progress-bar redraws and escape
/// codes removed) in `stdout`; stderr is merged into it in arrival order.
///
/// It handles two problems that come up in practice:
///  * installers that spawn long-lived grandchildren which inherit our pipes.
///    Once the direct child exits, we wait only a short grace period for EOF.
///  * hung tools, which are killed after `timeout`.
pub fn stream(mut command: Command, ctx: &RunContext, timeout: Duration) -> Result<CmdOutput, String> {
    let name = program_name(&command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not run `{name}`: {e}"))?;

    let (tx, rx) = mpsc::channel::<String>();
    if let Some(out) = child.stdout.take() {
        pump(out, tx.clone());
    }
    if let Some(err) = child.stderr.take() {
        pump(err, tx.clone());
    }
    drop(tx); // rx disconnects once both pumps hit EOF

    let started = Instant::now();
    let mut transcript = String::new();
    let mut status = None;
    let mut exited_at: Option<Instant> = None;

    loop {
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(raw) => {
                if let Some(line) = clean_progress_line(&raw) {
                    ctx.log(&line);
                    transcript.push_str(&line);
                    transcript.push('\n');
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(s)) => {
                    status = Some(s);
                    exited_at = Some(Instant::now());
                }
                Ok(None) if started.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(timed_out(&name, timeout));
                }
                Ok(None) => {}
                Err(e) => return Err(format!("lost track of `{name}`: {e}")),
            }
        }
        if exited_at.is_some_and(|t| t.elapsed() > Duration::from_secs(3)) {
            break; // a grandchild is holding the pipe open; don't wait on it
        }
    }

    // Pipes closed. If the child hasn't exited yet, keep waiting (with the timeout).
    let status = loop {
        if let Some(s) = status.take() {
            break s;
        }
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if started.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(timed_out(&name, timeout));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(150)),
            Err(e) => return Err(format!("lost track of `{name}`: {e}")),
        }
    };

    Ok(CmdOutput {
        code: status.code(),
        stdout: transcript,
        stderr: String::new(),
    })
}

fn timed_out(name: &str, timeout: Duration) -> String {
    format!(
        "`{name}` was stopped after {} without finishing",
        human_duration(timeout.as_secs())
    )
}

/// Read a pipe on its own thread, sending each *finished* line. A segment that
/// ends in a bare `\r` is a progress redraw ("45%… 46%…"): a terminal would
/// overwrite it, so it's dropped here too. `\r\n` still counts as a line end.
///
/// Some Windows tools (sfc, parts of DISM) write UTF-16LE when their output
/// is redirected. That's recognised from the stream's first bytes and decoded,
/// so their line ends are seen as line ends and their text reads correctly.
fn pump<R: Read + Send + 'static>(mut reader: R, tx: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut lines = LineSplitter { tx, line: Vec::new(), after_cr: false };
        let mut decoder: Option<Decoder> = None;
        // The first few bytes, held back until they're enough to tell the encoding.
        let mut head: Vec<u8> = Vec::new();
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let alive = match decoder.as_mut() {
                Some(d) => d.feed(&buf[..n], &mut lines),
                None => {
                    head.extend_from_slice(&buf[..n]);
                    let Some(d) = Decoder::detect(&head) else {
                        continue;
                    };
                    decoder.insert(d).feed(&std::mem::take(&mut head), &mut lines)
                }
            };
            if !alive {
                return;
            }
        }
        // Too short to tell the encoding: read what there is as bytes.
        if decoder.is_none() && !Decoder::Bytes.feed(&head, &mut lines) {
            return;
        }
        lines.finish();
    });
}

/// How a child's output is encoded.
enum Decoder {
    /// UTF-8, or a legacy code page read lossily.
    Bytes,
    Utf16Le {
        /// The first byte of a code unit split across two reads.
        half: Option<u8>,
        /// A high surrogate waiting for its low half.
        high: Option<u16>,
    },
}

impl Decoder {
    /// The encoding, once a stream's first bytes are enough to tell (`None`
    /// until then). UTF-16LE opens with its byte-order mark or, the usual
    /// case (sfc), is plain text with a zero after every character.
    fn detect(head: &[u8]) -> Option<Self> {
        let wide = Decoder::Utf16Le { half: None, high: None };
        match head {
            [0xFF, 0xFE, ..] => Some(wide),
            [a, 0, c, 0, ..] if *a != 0 && *c != 0 => Some(wide),
            [] | [_] | [_, 0] | [_, 0, _] => None, // could still be either
            _ => Some(Decoder::Bytes),
        }
    }

    /// Decode a chunk into `lines`. False once nobody is listening.
    fn feed(&mut self, chunk: &[u8], lines: &mut LineSplitter) -> bool {
        match self {
            Decoder::Bytes => chunk.iter().all(|&b| lines.push(u32::from(b), &[b])),
            Decoder::Utf16Le { half, high } => {
                for &b in chunk {
                    let Some(low) = half.take() else {
                        *half = Some(b);
                        continue;
                    };
                    let unit = u16::from_le_bytes([low, b]);
                    let ch = match unit {
                        0xFEFF => continue, // byte-order mark
                        0xD800..=0xDBFF => {
                            *high = Some(unit);
                            continue;
                        }
                        0xDC00..=0xDFFF => high
                            .take()
                            .and_then(|h| char::decode_utf16([h, unit]).next()?.ok())
                            .unwrap_or(char::REPLACEMENT_CHARACTER),
                        _ => {
                            *high = None;
                            char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER)
                        }
                    };
                    let mut utf8 = [0u8; 4];
                    if !lines.push(ch as u32, ch.encode_utf8(&mut utf8).as_bytes()) {
                        return false;
                    }
                }
                true
            }
        }
    }
}

/// Turns a stream of characters into finished lines, dropping progress redraws.
struct LineSplitter {
    tx: mpsc::Sender<String>,
    /// The line so far, as bytes (UTF-8, or a code page read lossily when sent).
    line: Vec<u8>,
    after_cr: bool,
}

impl LineSplitter {
    /// Take one character (or byte) and its encoded form. False once nobody
    /// is listening.
    fn push(&mut self, unit: u32, encoded: &[u8]) -> bool {
        // A NUL is never text. Skipping it here, before the line-end logic,
        // keeps UTF-16 that wasn't recognised as such readable: its `\r\0\n\0`
        // is still a line end, not a redraw.
        if unit == 0 {
            return true;
        }
        if self.after_cr {
            self.after_cr = false;
            if unit == u32::from(b'\n') {
                return self.send();
            }
            self.line.clear(); // bare CR: what came before was a redraw
        }
        match unit {
            0x0D => self.after_cr = true,
            0x0A => return self.send(),
            _ => self.line.extend_from_slice(encoded),
        }
        true
    }

    fn send(&mut self) -> bool {
        if self.line.is_empty() {
            return true;
        }
        let s = String::from_utf8_lossy(&self.line).into_owned();
        self.line.clear();
        if s.trim().is_empty() {
            return true;
        }
        self.tx.send(s).is_ok()
    }

    /// End of the stream: send what's left.
    fn finish(mut self) {
        let _ = self.send();
    }
}

// --------------------------------------------------------------- privileges

/// Shown when a Windows admin-only module runs without elevation.
pub const ADMIN_REQUIRED: &str = "Administrator rights required. Use \"Relaunch as admin\" \
     in the header (or right-click ITriage → Run as administrator).";

/// Fail fast unless the process is elevated (Windows install modules).
#[cfg(windows)]
pub fn require_admin() -> Result<(), String> {
    if crate::host::is_elevated() {
        Ok(())
    } else {
        Err(ADMIN_REQUIRED.to_string())
    }
}

/// Windows: fail fast unless elevated. Linux: modules ask for rights
/// through pkexec as they need them, so there's nothing to check up front.
pub fn require_admin_here() -> Result<(), String> {
    #[cfg(windows)]
    {
        require_admin()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// A command that runs `script` as root: directly when already root, otherwise
/// through pkexec, which shows the desktop's polkit password prompt. The GUI
/// itself never runs as root, because WebKitGTK and the desktop session don't
/// support that well. Returns the command and whether pkexec is in the way.
#[cfg(unix)]
pub fn privileged_shell(script: &str) -> Result<(Command, bool), String> {
    if crate::host::is_elevated() {
        let mut c = cmd("sh");
        c.arg("-c").arg(script);
        Ok((c, false))
    } else if command_exists("pkexec") {
        let mut c = cmd("pkexec");
        c.arg("sh").arg("-c").arg(script);
        Ok((c, true))
    } else {
        Err("Needs root: run itriage with sudo, or install polkit (pkexec) so it can ask for your password."
            .to_string())
    }
}

/// Run `program args…` as root *without* a shell: directly when already
/// root, otherwise through pkexec. Arguments are passed through untouched,
/// so nothing in them is ever interpreted. Returns the command and whether
/// pkexec is in the way.
#[cfg(unix)]
pub fn privileged(program: &str, args: &[&str]) -> Result<(Command, bool), String> {
    let path = find_in_path(program).ok_or_else(|| format!("`{program}` isn't installed."))?;
    if crate::host::is_elevated() {
        let mut c = cmd(&path);
        c.args(args);
        Ok((c, false))
    } else if command_exists("pkexec") {
        let mut c = cmd("pkexec");
        c.arg(&path).args(args);
        Ok((c, true))
    } else {
        Err("Needs root: run itriage with sudo, or install polkit (pkexec) so it can ask for your password."
            .to_string())
    }
}

/// pkexec's own exit codes: 126 = the password dialog was dismissed,
/// 127 = this account isn't allowed to authenticate as an admin.
#[cfg(unix)]
pub fn pkexec_error(code: Option<i32>) -> Option<&'static str> {
    match code {
        Some(126) => Some("Authentication was cancelled, so nothing was changed."),
        Some(127) => Some("Not authorized: this account can't get admin rights through polkit."),
        _ => None,
    }
}

// ---------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes_and_time() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_duration(90_061), "1d 1h 1m");
        assert_eq!(ago(30), "just now");
        assert_eq!(ago(14 * 60), "14m ago");
        assert_eq!(ago(3 * 3600 + 5), "3h ago");
        assert_eq!(ago(2 * 86_400), "2d ago");
    }

    #[test]
    fn exit_labels_show_hresults_in_hex() {
        assert_eq!(exit_label(Some(0)), "exit 0");
        assert_eq!(exit_label(Some(3010)), "exit 3010");
        assert_eq!(exit_label(Some(-1978335189)), "exit 0x8A15002B");
    }

    #[cfg(unix)]
    #[test]
    fn finds_programs_on_path() {
        assert!(command_exists("sh"));
        assert!(!command_exists("definitely-not-a-real-tool-xyz"));
    }

    #[cfg(unix)]
    #[test]
    fn stream_drops_redraws_and_merges_stderr() {
        let lines = std::sync::Mutex::new(Vec::<String>::new());
        let sink = |l: &str| lines.lock().unwrap().push(l.to_string());
        let ctx = RunContext::new(&sink);
        let mut c = cmd("sh");
        c.args(["-c", "printf 'step 10%%\\rstep 99%%\\rdone\\r\\nsecond\\n'; echo oops >&2; exit 3"]);
        let out = stream(c, &ctx, Duration::from_secs(10)).unwrap();
        assert_eq!(out.code, Some(3));
        let got = lines.lock().unwrap().clone();
        assert!(got.contains(&"done".to_string()), "{got:?}");
        assert!(got.contains(&"second".to_string()), "{got:?}");
        assert!(got.contains(&"oops".to_string()), "{got:?}");
        assert!(!got.iter().any(|l| l.contains('%')), "redraws leaked: {got:?}");
    }

    /// Hands out a few bytes per read, so code units and line ends straddle reads.
    struct Drip(Vec<u8>, usize);

    impl Read for Drip {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.len().min(self.1).min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }

    fn pumped(bytes: Vec<u8>, per_read: usize) -> Vec<String> {
        let (tx, rx) = mpsc::channel();
        pump(Drip(bytes, per_read), tx);
        rx.iter().collect()
    }

    fn utf16le(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn utf16_output_keeps_its_lines() {
        // What `sfc /scannow` writes when redirected: UTF-16LE, a blank line
        // first, progress redrawn with a bare CR.
        let sfc = "\r\nBeginning system scan.  This process will take some time.\r\n\r\n\
                   Verification 12% complete.\rVerification 100% complete.\r\n\
                   Windows Resource Protection found corrupt files and successfully repaired them.\r\n";
        let want = vec![
            "Beginning system scan.  This process will take some time.",
            "Verification 100% complete.",
            "Windows Resource Protection found corrupt files and successfully repaired them.",
        ];
        for per_read in [1, 3, 7, 4096] {
            assert_eq!(pumped(utf16le(sfc), per_read), want, "{per_read} byte(s) per read");
        }
        // Any language, a byte-order mark, and a character outside the BMP.
        let mut marked = vec![0xFF, 0xFE];
        marked.extend(utf16le("Überprüfung 100 % abgeschlossen. ✔ 😀\r\nスキャンが完了しました\r\n"));
        assert_eq!(pumped(marked, 5), vec!["Überprüfung 100 % abgeschlossen. ✔ 😀", "スキャンが完了しました"]);
    }

    #[test]
    fn byte_output_is_unchanged_and_stray_nuls_never_eat_a_line() {
        assert_eq!(pumped(b"step 10%\rstep 99%\rdone\r\nsecond\nlast".to_vec(), 2), vec!["done", "second", "last"]);
        assert_eq!(pumped("naïve ✔\n".as_bytes().to_vec(), 1), vec!["naïve ✔"], "UTF-8 split across reads");
        assert_eq!(pumped(b"ok\n".to_vec(), 4096), vec!["ok"]);
        assert_eq!(pumped(b"y".to_vec(), 4096), vec!["y"], "too short to tell the encoding");
        assert!(matches!(Decoder::detect(b"y\n"), Some(Decoder::Bytes)), "decided at once, so nothing is held back");
        assert!(Decoder::detect(b"\r\0").is_none() && matches!(Decoder::detect(b"\r\0\n\0"), Some(Decoder::Utf16Le { .. })));
        // UTF-16 that starts after some plain bytes isn't detected, but its
        // line ends still count and its ASCII still reads.
        let mut mixed = b"plain\r\n".to_vec();
        mixed.extend(utf16le("wide line\r\nnext\r\n"));
        assert_eq!(pumped(mixed, 4096), vec!["plain", "wide line", "next"]);
    }

    #[cfg(unix)]
    #[test]
    fn stream_times_out_hung_tools() {
        let ctx = RunContext::silent();
        let mut c = cmd("sh");
        c.args(["-c", "sleep 30"]);
        let started = Instant::now();
        let err = stream(c, &ctx, Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("stopped after"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn stream_does_not_wait_on_grandchildren_holding_the_pipe() {
        let ctx = RunContext::silent();
        let mut c = cmd("sh");
        // The backgrounded sleep inherits stdout and keeps the pipe open.
        c.args(["-c", "sleep 20 & echo finished"]);
        let started = Instant::now();
        let out = stream(c, &ctx, Duration::from_secs(60)).unwrap();
        assert_eq!(out.code, Some(0));
        assert!(out.stdout.contains("finished"));
        assert!(started.elapsed() < Duration::from_secs(10), "waited on the grandchild");
    }
}
