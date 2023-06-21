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

pub fn setup_logging() {
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
                Level::Trace => Color::White,
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
        .filter(None, LevelFilter::Debug)
        .parse_env(&env::var("RUST_LOG").unwrap_or_else(|_| "".to_owned()))
        .init();
}

pub fn create_options() -> (Options, Vec<&'static str>) {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("", "raw", "Interface to use", "enp2s0");
    opts.optopt("", "tun", "TUN interface to use", "tun0");
    opts.optopt("", "tap", "TAP interface to use", "tap0");
    opts.optopt(
        "",
        "ip",
        "Ip address to give the interface",
        "192.168.100.15",
    );
    opts.optopt(
        "",
        "mac",
        "Mac address to give the interface",
        "2A-22-53-43-11-59",
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

pub fn parse_tuntap_options(matches: &mut Matches) -> TunTapInterface {
    let tun = matches.opt_str("tun");
    let tap = matches.opt_str("tap");
    match (tun, tap) {
        (Some(tun), None) => TunTapInterface::new(&tun, Medium::Ip).unwrap(),
        (None, Some(tap)) => TunTapInterface::new(&tap, Medium::Ethernet).unwrap(),
        _ => panic!("You must specify exactly one of --tun or --tap"),
    }
}
