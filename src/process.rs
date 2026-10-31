//! One bounded, shell-free subprocess runner for the fixed-argv tools MIRA
//! executes (systemctl, ssh-keygen). Callers own argv and interpret status.
use std::{
    io::{self, Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Where the child's stderr goes. Interactive signing shows prompts; queries discard it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Stderr {
    Discard,
    Inherit,
}

/// Run `command`, optionally feeding `input` on stdin, and collect at most
/// `limit` stdout bytes under one deadline. Stdout is drained while exit is
/// monitored, even if an inherited writer keeps the pipe open after the
/// direct child exits. Returns as soon as the child has failed, or once it has
/// succeeded and stdout reached EOF. The direct child is always reaped.
pub(crate) fn run_bounded(
    command: &mut Command,
    input: Option<&[u8]>,
    stderr: Stderr,
    timeout: Duration,
    limit: usize,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let (mut reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    let start = Instant::now();
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(match stderr {
            Stderr::Discard => Stdio::null(),
            Stderr::Inherit => Stdio::inherit(),
        });
    let mut child = command.spawn()?;
    // Release Command's retained writer so it cannot prevent EOF.
    command.stdout(Stdio::null());
    // A separate writer keeps a child that never reads stdin from blocking us;
    // a child that exits early just ends the write with EPIPE.
    let feeder = match (input, child.stdin.take()) {
        (Some(input), Some(mut stdin)) => {
            let input = input.to_vec();
            Some(thread::spawn(move || {
                let _ = stdin.write_all(&input);
            }))
        }
        _ => None,
    };
    let result = (|| {
        let mut bytes = Vec::new();
        let mut eof = false;
        let mut status = None;
        loop {
            if start.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "subprocess timeout",
                ));
            }
            if !eof {
                let mut buffer = [0_u8; 1024];
                match reader.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        if bytes.len() + count > limit {
                            return Err(crate::collector::limit_exceeded());
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if let Some(status) = status
                && (eof || !status.success())
            {
                return Ok((status, bytes));
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    // Reap the direct child on every post-spawn return path.
    let _ = child.kill();
    let _ = child.wait();
    if let Some(feeder) = feeder {
        let _ = feeder.join();
    }
    result
}
