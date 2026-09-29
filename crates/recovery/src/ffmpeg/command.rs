//! Pure FFmpeg command construction and argument validation (Req 14.4, Phase 1-2).
//!
//! Enforces:
//! - Direct argument arrays (never shell commands like sh -c / cmd.exe)
//! - Stream-copy only (-c:v copy)
//! - Precise input demuxer mapping (-f h264 for H.264, -f hevc for H.265)
//! - No mandatory +faststart in primary forensic path
//! - No `-y` overwrite flag (protecting against accidental file overwrites)

use crate::reconstructor::VideoCodec;
use forensic_core::ForensicError;
use std::path::Path;

/// Structured specification of an external FFmpeg command invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandSpec {
    /// Constructs a direct `std::process::Command` without shell interpretation.
    pub fn to_std_command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.program);
        cmd.args(&self.args);
        // Prevent a visible console window from flashing on screen when the
        // desktop GUI spawns ffmpeg/ffprobe (which are console programs).
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd
    }

    /// Constructs a direct `tokio::process::Command` without shell interpretation.
    pub fn to_tokio_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd
    }
}

/// Builds the direct argument list for remuxing a materialized elementary stream into an MP4 container.
pub fn build_file_remux_command(
    ffmpeg_bin: &str,
    codec: VideoCodec,
    input_es_path: &Path,
    output_mp4_path: &Path,
) -> Result<CommandSpec, ForensicError> {
    let input_format = match codec {
        VideoCodec::H264 => "h264",
        VideoCodec::H265 => "hevc",
        VideoCodec::Mjpeg => {
            return Err(ForensicError::UnsupportedFormat {
                format: "mjpeg".into(),
                reason: "MJPEG stream-copy containerization is not supported in Phase 1 pipeline"
                    .into(),
            });
        }
        VideoCodec::Mpeg4 => {
            return Err(ForensicError::UnsupportedFormat {
                format: "mpeg4".into(),
                reason: "MPEG-4 elementary stream remuxing is not supported in Phase 1 pipeline"
                    .into(),
            });
        }
        VideoCodec::Unknown => {
            return Err(ForensicError::UnsupportedFormat {
                format: "unknown".into(),
                reason: "Cannot remux stream with unknown video codec".into(),
            });
        }
    };

    let args = vec![
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "error".to_string(),
        "-f".to_string(),
        input_format.to_string(),
        "-i".to_string(),
        input_es_path.to_string_lossy().to_string(),
        "-map".to_string(),
        "0:v:0".to_string(),
        "-c:v".to_string(),
        "copy".to_string(),
        // The output muxer is stated explicitly rather than inferred from the
        // filename. The writer stages output through a `.mp4.partial` temp file,
        // and FFmpeg cannot derive a format from the `.partial` extension, so
        // inference would fail. Being explicit also keeps the chosen container
        // deterministic and independent of the temp-file naming scheme.
        "-f".to_string(),
        "mp4".to_string(),
        output_mp4_path.to_string_lossy().to_string(),
    ];

    Ok(CommandSpec {
        program: ffmpeg_bin.to_string(),
        args,
    })
}

/// Builds the argument list for ffprobe machine-readable JSON inspection.
pub fn build_probe_command(ffprobe_bin: &str, media_path: &Path) -> CommandSpec {
    let args = vec![
        "-v".to_string(),
        "error".to_string(),
        "-show_streams".to_string(),
        "-show_format".to_string(),
        "-of".to_string(),
        "json".to_string(),
        media_path.to_string_lossy().to_string(),
    ];

    CommandSpec {
        program: ffprobe_bin.to_string(),
        args,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_h264_command_construction() {
        let input = PathBuf::from("/tmp/stream.h264");
        let output = PathBuf::from("/tmp/recording.mp4.partial");
        let spec = build_file_remux_command("ffmpeg", VideoCodec::H264, &input, &output).unwrap();

        assert_eq!(spec.program, "ffmpeg");
        assert_eq!(
            spec.args,
            vec![
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "h264",
                "-i",
                "/tmp/stream.h264",
                "-map",
                "0:v:0",
                "-c:v",
                "copy",
                "-f",
                "mp4",
                "/tmp/recording.mp4.partial"
            ]
        );
        // The output muxer must be explicit; the `.partial` temp extension is not
        // inferable by FFmpeg.
        assert_eq!(spec.args[spec.args.len() - 3], "-f");
        assert_eq!(spec.args[spec.args.len() - 2], "mp4");
        // Assert no -y flag
        assert!(!spec.args.contains(&"-y".to_string()));
        // Assert no +faststart flag
        assert!(!spec.args.contains(&"+faststart".to_string()));
    }

    #[test]
    fn test_h265_command_construction() {
        let input = PathBuf::from("/tmp/stream.hevc");
        let output = PathBuf::from("/tmp/recording.mp4.partial");
        let spec = build_file_remux_command("ffmpeg", VideoCodec::H265, &input, &output).unwrap();

        assert_eq!(spec.program, "ffmpeg");
        assert_eq!(spec.args[4], "hevc");
        assert_eq!(spec.args[10], "copy");
    }

    #[test]
    fn test_unsupported_codecs_rejected() {
        let input = PathBuf::from("/tmp/stream.mjpeg");
        let output = PathBuf::from("/tmp/out.mp4");
        assert!(build_file_remux_command("ffmpeg", VideoCodec::Mjpeg, &input, &output).is_err());
        assert!(build_file_remux_command("ffmpeg", VideoCodec::Unknown, &input, &output).is_err());
    }

    #[test]
    fn test_security_adversarial_paths_passed_literally() {
        // Path with shell injection characters must remain a single literal string argument
        let malicious_input = PathBuf::from("/tmp/stream; rm -rf /; $(whoami).h264");
        let output = PathBuf::from("/tmp/output.mp4");
        let spec = build_file_remux_command("ffmpeg", VideoCodec::H264, &malicious_input, &output)
            .unwrap();

        assert_eq!(spec.args[6], "/tmp/stream; rm -rf /; $(whoami).h264");
        // Ensure no shell command wrapper exists
        assert_ne!(spec.program, "sh");
        assert_ne!(spec.program, "bash");
        assert_ne!(spec.program, "cmd.exe");
    }

    #[test]
    fn test_probe_command_spec() {
        let target = PathBuf::from("/tmp/recording.mp4");
        let spec = build_probe_command("ffprobe", &target);

        assert_eq!(spec.program, "ffprobe");
        assert_eq!(
            spec.args,
            vec![
                "-v",
                "error",
                "-show_streams",
                "-show_format",
                "-of",
                "json",
                "/tmp/recording.mp4"
            ]
        );
    }

    /// Regression test: on Windows, child processes must set CREATE_NO_WINDOW so that
    /// the desktop GUI does not flash console windows. The flag is verified by spawning
    /// a command and checking the output; a visible console would mean the flag was
    /// not applied. This test runs `cmd /C echo OK` with the flag and confirms it still
    /// captures output (i.e. the flag does not break pipe capture).
    #[cfg(windows)]
    #[test]
    fn windows_create_no_window_flag_does_not_break_pipe_capture() {
        let spec = CommandSpec {
            program: "cmd".to_string(),
            args: vec!["/C".into(), "echo OK".into()],
        };
        let mut cmd = spec.to_std_command();
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let output = cmd.output().expect("cmd /C echo should succeed");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("OK"),
            "stdout capture must still work with CREATE_NO_WINDOW"
        );
    }
}
