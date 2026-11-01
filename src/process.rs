//! One bounded, shell-free subprocess runner for the fixed-argv tools MIRA
//! executes (systemctl, journalctl, ssh-keygen). Callers own argv and interpret status.
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
/// `limit` stdout bytes under one deadline. Stdin is written and stdout drained
/// nonblockingly in the same loop, so neither a child that never reads nor a
/// descendant that keeps either stream open can extend the deadline. Returns
/// as soon as the child has failed, or once it has succeeded and stdout reached
/// EOF. The direct child is always reaped.
pub(crate) fn run_bounded(
    command: &mut Command,
    input: Option<&[u8]>,
    stderr: Stderr,
    timeout: Duration,
    limit: usize,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let (mut reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    // Input travels over its own socket so writes can be nonblocking too.
    let mut feed = match input {
        Some(input) => {
            let (parent, child) = UnixStream::pair()?;
            parent.set_nonblocking(true)?;
            command.stdin(Stdio::from(OwnedFd::from(child)));
            Some((parent, input))
        }
        None => {
            command.stdin(Stdio::null());
            None
        }
    };
    let start = Instant::now();
    command
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(match stderr {
            Stderr::Discard => Stdio::null(),
            Stderr::Inherit => Stdio::inherit(),
        });
    let mut child = command.spawn()?;
    // Release Command's retained child ends so they cannot prevent EOF.
    command.stdin(Stdio::null()).stdout(Stdio::null());
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
            if let Some((stream, rest)) = &mut feed {
                match stream.write(rest) {
                    Ok(count) => {
                        *rest = &rest[count..];
                        if rest.is_empty() {
                            // Dropping the parent end delivers EOF on stdin.
                            feed = None;
                        }
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    // The child closed stdin early; its exit status decides.
                    Err(error) if error.kind() == io::ErrorKind::BrokenPipe => feed = None,
                    Err(error) => return Err(error),
                }
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
    // Reap the direct child on every post-spawn return path. Any unsent input
    // is dropped with `feed`; nothing waits on a descendant.
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_that_a_descendant_holds_cannot_outlive_the_deadline() {
        // The direct child never reads stdin and a descendant keeps the read end
        // open after the child is killed, as a stalled SSH_ASKPASS helper can.
        // Input larger than any pipe or socket buffer forces a blocked write.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 3 & sleep 10"]);
        let input = vec![b'x'; 4 * 1024 * 1024];
        let start = Instant::now();
        let error = run_bounded(
            &mut command,
            Some(&input),
            Stderr::Discard,
            Duration::from_millis(200),
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "returned after {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn input_is_delivered_completely_before_eof() {
        // A reader that consumes all of stdin and reports its length.
        let mut command = Command::new("/usr/bin/wc");
        command.arg("-c");
        let input = vec![b'y'; 3 * 1024 * 1024 + 7];
        let (status, output) = run_bounded(
            &mut command,
            Some(&input),
            Stderr::Discard,
            Duration::from_secs(10),
            64,
        )
        .unwrap();
        assert!(status.success());
        assert_eq!(String::from_utf8(output).unwrap().trim(), "3145735");
    }
}
