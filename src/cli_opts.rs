#![allow(dead_code)]

use env_logger::fmt::Color;
use env_logger::Builder;
use getopts::{Matches, Options};
use log::*;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process;
use std::str::{self, FromStr};
use std::time::{SystemTime, UNIX_EPOCH};

use smoltcp::phy::RawSocket;
use smoltcp::phy::TunTapInterface;
use smoltcp::phy::{Device, FaultInjector, Medium, Tracer};
use smoltcp::phy::{PcapMode, PcapWriter};
use smoltcp::time::{Duration, Instant};

pub fn setup_logging(level: LevelFilter) {
    Builder::new()
        .format(|buf, record| {
            // Get the file name and line number from the record
            let file = record.file().unwrap_or("unknown");
            let line = record.line().unwrap_or(0);

            // Get the color for the log level
            let color = match record.level() {
                Level::Error => Color::Red,
                Level::Warn => Color::Yellow,
                Level::Info => Color::Green,
                Level::Debug => Color::Cyan,
                Level::Trace => Color::Black,
            };

            // Write the formatted output to the buffer
            writeln!(
                buf,
                "{}:{} [{}] {}",
                file,
                line,
                buf.style().set_color(color).value(record.level()),
                record.args()
            )
        })
        .filter(None, level)
        .parse_env(&env::var("RUST_LOG").unwrap_or_else(|_| "".to_owned()))
        .init();
}

pub fn create_options() -> (Options, Vec<&'static str>) {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("i", "interface", "Interface to use", "enp2s0");
    opts.optopt("", "ipxe", "Path to custom ipxe image", "./build/ipxe.pxe");
    opts.optflag("", "raw", "Interface to use");
    opts.optflag("", "tun", "TUN interface to use");
    opts.optflag("", "tap", "TAP interface to use");
    opts.optopt(
        "l",
        "level",
        "debug level",
        "[OFF, ERROR, WARN, INFO, DEBUG, TRACE]",
    );
    (opts, Vec::new())
}

pub fn parse_options(options: &Options, free: Vec<&str>) -> Matches {
    match options.parse(env::args().skip(1)) {
        Err(err) => {
            println!("{}", err);
            process::exit(1)
        }
        Ok(matches) => {
            if matches.opt_present("h") || matches.free.len() != free.len() {
                let brief = format!(
                    "Usage: {} [OPTION]... {}",
                    env::args().next().unwrap(),
                    free.join(" ")
                );
                print!("{}", options.usage(&brief));
                process::exit(if matches.free.len() != free.len() {
                    1
                } else {
                    0
                })
            }
            matches
        }
    }
}
