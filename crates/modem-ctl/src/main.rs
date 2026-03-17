//! modem-ctl — AT command helper for USR modem
//!
//! Usage:
//!   modem-ctl <device> reset
//!   modem-ctl <device> dial <number>
//!
//! `reset` puts the modem in a known state (ATV1, ATE1).
//! `dial`  runs reset, dials, waits for CONNECT, then execs pppd on the live fd.

use clap::{Parser, Subcommand};
use serialport::{SerialPort, TTYPort};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "modem-ctl")]
struct Args {
    /// Serial device (e.g. /dev/ttyUSB0)
    device: String,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Reset modem to known state (ATZ, ATV1, ATE1) then exit
    Reset,
    /// Dial a number, wait for CONNECT, then exec pppd
    Dial {
        /// Phone number to dial
        number: String,
        /// pppd arguments (space-separated)
        #[arg(long, default_value = "noauth nodetach debug lcp-max-configure 30")]
        pppd_args: String,
    },
}

const BAUD: u32 = 115200;

fn main() {
    let args = Args::parse();

    // open_native() gives us a TTYPort which implements AsRawFd (needed for dial)
    let mut port: TTYPort = serialport::new(&args.device, BAUD)
        .timeout(Duration::from_millis(200))
        .open_native()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open {}: {}", args.device, e);
            std::process::exit(1);
        });

    match args.command {
        Cmd::Reset => {
            reset_modem(&mut port);
            println!("[OK] modem ready");
        }
        Cmd::Dial { number, pppd_args } => {
            reset_modem(&mut port);
            dial_and_exec(&mut port, &args.device, &number, &pppd_args);
        }
    }
}

/// Send `+++` escape + 1.2s pause, then ATH / ATZ / ATV1 / ATE1.
fn reset_modem(port: &mut dyn SerialPort) {
    // Escape to command mode (in case mid-call)
    eprint!("Sending +++ escape... ");
    let _ = port.write_all(b"+++");
    let _ = port.flush();
    std::thread::sleep(Duration::from_millis(1200));
    drain(port);
    eprintln!("done");

    send_at(port, "ATH\r", &["OK", "0"], 3);
    send_at(port, "ATZ\r", &["OK", "0"], 5);
    send_at(port, "ATV1\r", &["OK"], 3);
    send_at(port, "ATE1\r", &["OK"], 3);
}

/// Dial, wait for CONNECT, then exec pppd with the open fd.
fn dial_and_exec(port: &mut TTYPort, _device: &str, number: &str, pppd_args: &str) {
    let cmd = format!("ATDT{}\r", number);
    eprint!("Dialing {}... ", number);
    let _ = port.write_all(cmd.as_bytes());
    let _ = port.flush();

    // Wait up to 120 s for CONNECT
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut response = String::new();

    loop {
        if Instant::now() > deadline {
            eprintln!("\n[FAIL] Timeout waiting for CONNECT");
            std::process::exit(1);
        }

        let mut buf = [0u8; 64];
        match port.read(&mut buf) {
            Ok(n) if n > 0 => {
                let chunk = String::from_utf8_lossy(&buf[..n]);
                eprint!("{}", chunk);
                response.push_str(&chunk);
                if response.contains("CONNECT") {
                    eprintln!("\n[OK] Connected");
                    break;
                }
                if response.contains("NO CARRIER")
                    || response.contains("BUSY")
                    || response.contains("NO ANSWER")
                    || response.contains("ERROR")
                {
                    eprintln!("\n[FAIL] Modem: {}", response.trim());
                    std::process::exit(1);
                }
            }
            Ok(_) | Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    // dup2 the serial fd onto stdin (fd 0).  Modern pppd (≥2.5) removed the
    // 'fd <N>' option; when given no device argument pppd uses tty_fd=0 and
    // inherits the already-configured termios (115200, raw).
    let raw_fd = port.as_raw_fd();
    if unsafe { libc::dup2(raw_fd, 0) } < 0 {
        eprintln!("[FAIL] dup2: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    // Build pppd argv: just the user-supplied options (no device/baud/fd).
    let argv: Vec<String> = pppd_args.split_whitespace().map(|s| s.to_string()).collect();

    eprintln!("exec pppd {}", argv.join(" "));

    // exec replaces the process image; port's destructor never runs on success.
    // On failure, we exit explicitly.
    let err = std::process::Command::new("pppd").args(&argv).exec();
    eprintln!("[FAIL] exec pppd failed: {}", err);
    std::process::exit(1);
}

/// Send an AT command and wait for one of the expected strings.
fn send_at(port: &mut dyn SerialPort, cmd: &str, expect: &[&str], timeout_secs: u64) {
    eprint!("  {} -> ", cmd.trim());
    let _ = port.write_all(cmd.as_bytes());
    let _ = port.flush();

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut response = String::new();

    loop {
        if Instant::now() > deadline {
            eprintln!("TIMEOUT (got: {:?})", response.trim());
            std::process::exit(1);
        }

        let mut buf = [0u8; 64];
        match port.read(&mut buf) {
            Ok(n) if n > 0 => {
                response.push_str(&String::from_utf8_lossy(&buf[..n]));
                if expect.iter().any(|&e| response.contains(e)) {
                    eprintln!("OK");
                    return;
                }
            }
            Ok(_) | Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Drain pending bytes from the port.
fn drain(port: &mut dyn SerialPort) {
    let mut buf = [0u8; 256];
    loop {
        match port.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
