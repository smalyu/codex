#![deny(clippy::print_stdout)]

use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::path::Path;
use std::thread;

use anyhow::Context;
use anyhow::anyhow;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use std::os::windows::net::UnixStream;

/// Connects to the Unix Domain Socket at `socket_path` and relays data between
/// standard input/output and the socket.
pub fn run(socket_path: &Path) -> anyhow::Result<()> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to socket at {}", socket_path.display()))?;

    let stdin = io::stdin();
    let stdout = io::stdout();

    relay(stream, stdin, stdout)
}

/// Relays data between the socket `stream`, the given input, and output
/// handles. Tests use this helper to inject custom IO streams.
pub fn relay<R, W>(mut stream: UnixStream, mut input: R, output: W) -> anyhow::Result<()>
where
    R: Read,
    W: Write + Send + 'static,
{
    let mut reader = stream
        .try_clone()
        .context("failed to clone socket for reading")?;

    let stdout_thread = thread::spawn(move || -> io::Result<()> {
        let mut output = output;
        io::copy(&mut reader, &mut output)?;
        output.flush()?;
        Ok(())
    });

    io::copy(&mut input, &mut stream).context("failed to copy data from input to socket")?;
    stream
        .shutdown(Shutdown::Write)
        .context("failed to shutdown socket writer")?;

    let stdout_result = stdout_thread
        .join()
        .map_err(|_| anyhow!("thread panicked while copying socket data to output"))?;
    stdout_result.context("failed to copy data from socket to output")?;

    Ok(())
}
