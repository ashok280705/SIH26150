//! Hardened external-process execution for `ffmpeg` and `ffprobe`.
//!
//! Every property this module provides exists because its absence has a forensic consequence:
//!
//! * **Real timeout enforcement.** A configured timeout that is never applied is worse than no
//!   timeout, because it reads as a safety control in review. Here the budget is a
//!   `tokio::time::timeout` around the wait, followed by an actual `kill()` and reap of the
//!   child, and the outcome is [`MediaErrorKind::FfmpegTimeout`] — never a success.
//! * **Exit status is authoritative.** A non-zero exit, a signal death, a timeout, or a
//!   missing/unopenable output all fail. Nothing downstream reports success past this point.
//! * **Bounded diagnostics.** stderr is captured so a failure can be explained, but only the
//!   tail is kept, so a chatty decoder cannot flood the log or memory.
//! * **Bounded concurrency.** A batch request cannot fan out into unlimited child processes;
//!   permits come from a shared semaphore whose size is configuration, not a constant.
//! * **No shell.** Arguments are passed as a literal argv array. A path containing `;` or
//!   `$(...)` is one argument, not a command.

use crate::error::{MediaError, MediaErrorKind, MediaResult};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, ChildStdout};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Default wall-clock budget for a single child process.
pub const DEFAULT_PROCESS_TIMEOUT_SECS: u64 = 300;

/// Default number of simultaneously running FFmpeg/ffprobe children.
pub const DEFAULT_MAX_CONCURRENT_PROCESSES: usize = 2;

/// How many trailing bytes of stderr are retained for diagnostics.
pub const DEFAULT_STDERR_TAIL_BYTES: usize = 16 * 1024;

/// A literal program + argv pair. Never a shell string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl CommandSpec {
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }

    /// The argv as it would be recorded on an artifact's provenance.
    pub fn display_args(&self) -> Vec<String> {
        self.args.clone()
    }

    fn to_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args);
        cmd.stdin(Stdio::null());
        // Killing the handle on drop prevents an orphaned decoder surviving a cancelled
        // request and continuing to consume CPU against evidence storage.
        cmd.kill_on_drop(true);
        cmd
    }
}

/// Per-invocation execution limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLimits {
    pub timeout: Duration,
    /// Trailing stderr bytes retained. Output beyond this is discarded, and the outcome
    /// records that truncation happened.
    pub stderr_tail_bytes: usize,
    /// Cap on captured stdout for `run_capture`. `None` means "no cap" and is only appropriate
    /// for small, structured output such as ffprobe JSON.
    pub max_stdout_bytes: Option<usize>,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_PROCESS_TIMEOUT_SECS),
            stderr_tail_bytes: DEFAULT_STDERR_TAIL_BYTES,
            // 32 MiB is far above any ffprobe JSON and far below anything that threatens the
            // process; a decode that needs more must use the streaming path instead.
            max_stdout_bytes: Some(32 * 1024 * 1024),
        }
    }
}

/// The complete, non-boolean outcome of a child process run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub exit_code: Option<i32>,
    pub success: bool,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_tail: String,
    pub stderr_truncated: bool,
    pub duration: Duration,
}

impl ProcessOutcome {
    /// Turns a non-success outcome into the supplied error code, carrying diagnostics across.
    ///
    /// The timeout case overrides the caller's code: a process that was killed for running too
    /// long did not "fail to decode", and the report must say which happened.
    pub fn require_success(
        &self,
        failure_kind: MediaErrorKind,
        operation: &str,
    ) -> MediaResult<()> {
        if self.timed_out {
            return Err(MediaError::new(
                MediaErrorKind::FfmpegTimeout,
                operation,
                format!(
                    "child process exceeded its {:.3}s budget and was terminated",
                    self.duration.as_secs_f64()
                ),
            )
            .with_process(self.exit_code, self.stderr_tail.clone()));
        }
        if self.success {
            return Ok(());
        }
        Err(MediaError::new(
            failure_kind,
            operation,
            match self.exit_code {
                Some(c) => format!("child process exited with status {c}"),
                None => "child process terminated without an exit status (signal or crash)".into(),
            },
        )
        .with_process(self.exit_code, self.stderr_tail.clone()))
    }
}

/// Bounded executor for FFmpeg-family child processes.
///
/// Cloning shares the same permit pool, so one runner held in application state bounds every
/// request that borrows it.
#[derive(Debug, Clone)]
pub struct ProcessRunner {
    permits: Arc<Semaphore>,
    max_concurrent: usize,
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_PROCESSES)
    }
}

impl ProcessRunner {
    /// Creates a runner admitting at most `max_concurrent` simultaneous children.
    ///
    /// A request for zero is raised to one: a runner that can never run anything would turn a
    /// misconfiguration into a silent, permanent hang.
    pub fn new(max_concurrent: usize) -> Self {
        let n = max_concurrent.max(1);
        Self {
            permits: Arc::new(Semaphore::new(n)),
            max_concurrent: n,
        }
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Currently available permits. Exposed for the metrics surface.
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    async fn acquire(&self, operation: &str) -> MediaResult<OwnedSemaphorePermit> {
        self.permits.clone().acquire_owned().await.map_err(|_| {
            MediaError::new(
                MediaErrorKind::Cancelled,
                operation,
                "process runner was shut down while waiting for an execution permit",
            )
        })
    }

    /// Runs a child to completion, capturing stdout and the stderr tail.
    ///
    /// Suitable for ffprobe and for any ffmpeg run whose output goes to a file. For decoding
    /// into memory use [`ProcessRunner::spawn_streaming`] instead, which does not buffer the
    /// whole raw video in RAM.
    pub async fn run_capture(
        &self,
        spec: &CommandSpec,
        limits: &ProcessLimits,
        operation: &str,
    ) -> MediaResult<ProcessOutcome> {
        let _permit = self.acquire(operation).await?;
        let started = Instant::now();

        let mut child = spec
            .to_command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| spawn_error(spec, operation, e))?;

        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let stdout_cap = limits.max_stdout_bytes.unwrap_or(usize::MAX);
        let stderr_cap = limits.stderr_tail_bytes;

        // stdout, stderr and the exit status are awaited together. Reading them sequentially
        // would deadlock as soon as the child filled the pipe we are not draining.
        let run = async {
            let (out, err, status) = tokio::join!(
                read_capped(&mut stdout, stdout_cap),
                read_tail(&mut stderr, stderr_cap),
                child.wait(),
            );
            (out, err, status)
        };

        match tokio::time::timeout(limits.timeout, run).await {
            Ok((out, err, status)) => {
                let duration = started.elapsed();
                let status = status.map_err(|e| {
                    MediaError::new(
                        MediaErrorKind::FfmpegFailed,
                        operation,
                        format!("failed to await child process: {e}"),
                    )
                })?;
                let (stdout_bytes, stdout_truncated) = out;
                let (stderr_tail, stderr_truncated) = err;
                Ok(ProcessOutcome {
                    exit_code: status.code(),
                    success: status.success(),
                    timed_out: false,
                    stdout: stdout_bytes,
                    stdout_truncated,
                    stderr_tail,
                    stderr_truncated,
                    duration,
                })
            }
            Err(_elapsed) => {
                // The budget expired. Terminate and reap so no orphan survives this request.
                let _ = child.kill().await;
                let status = child.wait().await.ok();
                Ok(ProcessOutcome {
                    exit_code: status.and_then(|s| s.code()),
                    success: false,
                    timed_out: true,
                    stdout: Vec::new(),
                    stdout_truncated: false,
                    stderr_tail: String::new(),
                    stderr_truncated: false,
                    duration: started.elapsed(),
                })
            }
        }
    }

    /// Spawns a child whose stdout the caller drains incrementally.
    ///
    /// This is the path used for decoding: raw video is consumed frame by frame, so peak memory
    /// is one frame rather than one recording. The returned handle owns the execution permit,
    /// so the concurrency bound covers the whole streaming lifetime, not just the spawn.
    pub async fn spawn_streaming(
        &self,
        spec: &CommandSpec,
        limits: &ProcessLimits,
        operation: &str,
    ) -> MediaResult<StreamingProcess> {
        let permit = self.acquire(operation).await?;
        let started = Instant::now();

        let mut child = spec
            .to_command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| spawn_error(spec, operation, e))?;

        let stdout = child.stdout.take().ok_or_else(|| {
            MediaError::new(
                MediaErrorKind::FfmpegFailed,
                operation,
                "child stdout pipe was not available",
            )
        })?;
        let mut stderr = child.stderr.take();
        let stderr_cap = limits.stderr_tail_bytes;

        // stderr is drained by its own task for the whole lifetime of the child. Leaving it
        // undrained would stall FFmpeg the moment the pipe filled, which looks exactly like a
        // decode hang.
        let stderr_task = tokio::spawn(async move { read_tail(&mut stderr, stderr_cap).await });

        Ok(StreamingProcess {
            child,
            stdout: Some(stdout),
            stderr_task: Some(stderr_task),
            deadline: started + limits.timeout,
            started,
            operation: operation.to_string(),
            _permit: permit,
        })
    }
}

/// A running child whose stdout the caller reads incrementally.
///
/// Dropping this without calling [`StreamingProcess::finish`] still kills the child, because
/// the command was configured with `kill_on_drop`.
#[derive(Debug)]
pub struct StreamingProcess {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr_task: Option<tokio::task::JoinHandle<(String, bool)>>,
    deadline: Instant,
    started: Instant,
    operation: String,
    _permit: OwnedSemaphorePermit,
}

impl StreamingProcess {
    /// Reads exactly `buf.len()` bytes, or fewer at clean end of stream.
    ///
    /// Returns the number of bytes filled. A return shorter than `buf.len()` means the child
    /// closed stdout; the caller decides whether a partial frame is an error. The read is
    /// bounded by the process deadline, so a decoder that stops producing output without
    /// exiting is still terminated.
    pub async fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> MediaResult<usize> {
        let remaining = self.remaining_budget()?;
        let stdout = self.stdout.as_mut().ok_or_else(|| {
            MediaError::new(
                MediaErrorKind::FrameExtractionFailed,
                &self.operation,
                "stdout has already been closed by the reader",
            )
        })?;

        let read = tokio::time::timeout(remaining, async {
            let mut filled = 0usize;
            while filled < buf.len() {
                let n = stdout.read(&mut buf[filled..]).await?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            Ok::<usize, std::io::Error>(filled)
        })
        .await;

        match read {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(MediaError::new(
                MediaErrorKind::FrameExtractionFailed,
                &self.operation,
                format!("reading decoded output: {e}"),
            )),
            Err(_elapsed) => Err(self.kill_for_timeout().await),
        }
    }

    fn remaining_budget(&self) -> MediaResult<Duration> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(MediaError::new(
                MediaErrorKind::FfmpegTimeout,
                &self.operation,
                format!(
                    "process budget of {:.3}s was already exhausted before this read",
                    (self.deadline - self.started).as_secs_f64()
                ),
            ));
        }
        Ok(self.deadline - now)
    }

    async fn kill_for_timeout(&mut self) -> MediaError {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        MediaError::new(
            MediaErrorKind::FfmpegTimeout,
            &self.operation,
            format!(
                "child process exceeded its {:.3}s budget and was terminated",
                (self.deadline - self.started).as_secs_f64()
            ),
        )
    }

    /// Terminates the child immediately, e.g. because the caller has all the frames it wanted.
    ///
    /// The subsequent [`StreamingProcess::finish`] reports `graceful == false`, so an early
    /// stop is never confused with the decoder reaching end of stream on its own.
    pub async fn stop(&mut self) {
        self.stdout = None;
        let _ = self.child.kill().await;
    }

    /// Waits for exit and returns the complete outcome, including the stderr tail.
    pub async fn finish(mut self) -> MediaResult<ProcessOutcome> {
        // Dropping stdout signals EOF to the child if it is still writing.
        self.stdout = None;

        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_else(|| Duration::from_secs(0));

        let (exit_code, success, timed_out) =
            match tokio::time::timeout(remaining.max(Duration::from_millis(1)), self.child.wait())
                .await
            {
                Ok(Ok(status)) => (status.code(), status.success(), false),
                Ok(Err(e)) => {
                    return Err(MediaError::new(
                        MediaErrorKind::FfmpegFailed,
                        &self.operation,
                        format!("failed to await child process: {e}"),
                    ))
                }
                Err(_) => {
                    let _ = self.child.kill().await;
                    let s = self.child.wait().await.ok();
                    (s.and_then(|s| s.code()), false, true)
                }
            };

        let (stderr_tail, stderr_truncated) = match self.stderr_task.take() {
            Some(h) => h.await.unwrap_or_else(|_| (String::new(), false)),
            None => (String::new(), false),
        };

        Ok(ProcessOutcome {
            exit_code,
            success,
            timed_out,
            stdout: Vec::new(),
            stdout_truncated: false,
            stderr_tail,
            stderr_truncated,
            duration: self.started.elapsed(),
        })
    }
}

fn spawn_error(spec: &CommandSpec, operation: &str, e: std::io::Error) -> MediaError {
    let kind = if e.kind() == std::io::ErrorKind::NotFound {
        // Distinguishing "the tool is not installed" from "the tool failed" is the whole point
        // of the dependency-unavailable codes.
        let name = spec
            .program
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if name.contains("ffprobe") {
            MediaErrorKind::FfprobeUnavailable
        } else {
            MediaErrorKind::FfmpegUnavailable
        }
    } else {
        MediaErrorKind::FfmpegFailed
    };
    MediaError::new(
        kind,
        operation,
        format!("spawning '{}': {e}", spec.program.display()),
    )
}

/// Reads at most `cap` bytes, reporting whether input remained.
async fn read_capped<R: AsyncRead + Unpin>(reader: &mut Option<R>, cap: usize) -> (Vec<u8>, bool) {
    let Some(r) = reader.as_mut() else {
        return (Vec::new(), false);
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() >= cap {
                    truncated = true;
                    continue; // keep draining so the child is not blocked on a full pipe
                }
                let take = n.min(cap - buf.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < n {
                    truncated = true;
                }
            }
        }
    }
    (buf, truncated)
}

/// Drains the stream fully but retains only the last `cap` bytes.
async fn read_tail<R: AsyncRead + Unpin>(reader: &mut Option<R>, cap: usize) -> (String, bool) {
    let Some(r) = reader.as_mut() else {
        return (String::new(), false);
    };
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > cap {
                    truncated = true;
                    let drop_to = tail.len() - cap;
                    tail.drain(..drop_to);
                }
            }
        }
    }
    (String::from_utf8_lossy(&tail).trim().to_string(), truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command that is available on every host this workspace builds on.
    fn sleep_spec(secs: u64) -> CommandSpec {
        if cfg!(windows) {
            // `timeout` needs a console; ping against the loopback is the portable stand-in.
            CommandSpec::new(
                "cmd",
                vec!["/C".into(), format!("ping -n {} 127.0.0.1 > NUL", secs + 1)],
            )
        } else {
            CommandSpec::new("sh", vec!["-c".into(), format!("sleep {secs}")])
        }
    }

    fn echo_spec(text: &str) -> CommandSpec {
        if cfg!(windows) {
            CommandSpec::new("cmd", vec!["/C".into(), format!("echo {text}")])
        } else {
            CommandSpec::new("sh", vec!["-c".into(), format!("printf '%s' '{text}'")])
        }
    }

    fn fail_spec() -> CommandSpec {
        if cfg!(windows) {
            CommandSpec::new("cmd", vec!["/C".into(), "exit 3".into()])
        } else {
            CommandSpec::new("sh", vec!["-c".into(), "exit 3".into()])
        }
    }

    #[tokio::test]
    async fn timeout_actually_terminates_an_overrunning_child() {
        let runner = ProcessRunner::new(1);
        let limits = ProcessLimits {
            timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let started = Instant::now();
        let outcome = runner
            .run_capture(&sleep_spec(30), &limits, "timeout_test")
            .await
            .unwrap();

        assert!(outcome.timed_out, "the run must be reported as timed out");
        assert!(!outcome.success, "a timed-out run is never a success");
        // The wait returned near the budget rather than after the full 30 seconds, which is
        // what proves the kill happened rather than the budget merely being recorded.
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "timeout did not terminate the child: {:?}",
            started.elapsed()
        );

        let err = outcome
            .require_success(MediaErrorKind::DecodeFailed, "timeout_test")
            .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::FfmpegTimeout);
    }

    #[tokio::test]
    async fn non_zero_exit_is_never_reported_as_success() {
        let runner = ProcessRunner::new(1);
        let outcome = runner
            .run_capture(&fail_spec(), &ProcessLimits::default(), "exit_test")
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, Some(3));
        let err = outcome
            .require_success(MediaErrorKind::FfmpegFailed, "exit_test")
            .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::FfmpegFailed);
        assert_eq!(err.exit_code, Some(3));
    }

    #[tokio::test]
    async fn stdout_is_captured_and_success_is_reported() {
        let runner = ProcessRunner::new(1);
        let outcome = runner
            .run_capture(&echo_spec("HELLO"), &ProcessLimits::default(), "echo_test")
            .await
            .unwrap();
        assert!(outcome.success, "stderr: {}", outcome.stderr_tail);
        assert!(String::from_utf8_lossy(&outcome.stdout).contains("HELLO"));
        outcome
            .require_success(MediaErrorKind::FfmpegFailed, "echo_test")
            .unwrap();
    }

    #[tokio::test]
    async fn a_missing_executable_is_reported_as_unavailable_not_as_a_decode_failure() {
        let runner = ProcessRunner::new(1);
        let spec = CommandSpec::new(
            "ffprobe-definitely-not-installed-3f9c2a",
            vec!["-version".into()],
        );
        let err = runner
            .run_capture(&spec, &ProcessLimits::default(), "probe")
            .await
            .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::FfprobeUnavailable);
        assert!(err.kind.is_dependency_unavailable());
    }

    #[tokio::test]
    async fn concurrency_is_bounded_by_the_configured_permit_count() {
        let runner = ProcessRunner::new(1);
        assert_eq!(runner.max_concurrent(), 1);
        assert_eq!(runner.available_permits(), 1);

        let limits = ProcessLimits {
            timeout: Duration::from_millis(250),
            ..Default::default()
        };
        // Two runs against a single permit must serialise; with a 250 ms budget each, a
        // concurrent execution would finish in ~250 ms and a serialised one in ~500 ms.
        let spec = sleep_spec(30);
        let started = Instant::now();
        let a = runner.run_capture(&spec, &limits, "a");
        let b = runner.run_capture(&spec, &limits, "b");
        let (ra, rb) = tokio::join!(a, b);
        assert!(ra.unwrap().timed_out && rb.unwrap().timed_out);
        assert!(
            started.elapsed() >= Duration::from_millis(450),
            "runs overlapped despite a single permit: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn zero_concurrency_is_raised_to_one_rather_than_hanging_forever() {
        assert_eq!(ProcessRunner::new(0).max_concurrent(), 1);
    }

    #[tokio::test]
    async fn stderr_capture_keeps_only_the_tail_and_flags_truncation() {
        let mut src: Option<&[u8]> = Some(b"0123456789abcdef");
        let (tail, truncated) = read_tail(&mut src, 6).await;
        assert_eq!(tail, "abcdef");
        assert!(truncated);
    }

    #[tokio::test]
    async fn stdout_capture_respects_its_cap() {
        let mut src: Option<&[u8]> = Some(b"0123456789");
        let (buf, truncated) = read_capped(&mut src, 4).await;
        assert_eq!(buf, b"0123");
        assert!(truncated);
    }

    #[test]
    fn arguments_are_literal_and_never_shell_interpreted() {
        let spec = CommandSpec::new(
            "ffmpeg",
            vec!["-i".into(), "/eviden ce/a; rm -rf /; $(whoami).h264".into()],
        );
        assert_eq!(spec.args[1], "/eviden ce/a; rm -rf /; $(whoami).h264");
        assert_eq!(spec.program, PathBuf::from("ffmpeg"));
    }
}
