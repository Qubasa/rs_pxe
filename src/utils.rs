#![allow(dead_code)]

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

pub fn setup_logging_with_clock<F>(filter: &str, since_startup: F)
where
    F: Fn() -> Instant + Send + Sync + 'static,
{
    Builder::new()
        .format(move |buf, record| {
            let elapsed = since_startup();
            let timestamp = format!("[{}]", elapsed);
            if record.target().starts_with("smoltcp::") {
                writeln!(
                    buf,
                    "\x1b[0m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target().replace("smoltcp::", ""),
                    record.args()
                )
            } else if record.level() == Level::Trace {
                let message = format!("{}", record.args());
                writeln!(
                    buf,
                    "\x1b[37m{} {}\x1b[0m",
                    timestamp,
                    message.replace('\n', "\n             ")
                )
            } else {
                writeln!(
                    buf,
                    "\x1b[32m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target(),
                    record.args()
                )
            }
        })
        .filter(None, LevelFilter::Trace)
        .parse_env(filter)
        .parse_env(&env::var("RUST_LOG").unwrap_or_else(|_| "".to_owned()))
        .init();
}

pub fn setup_logging(filter: &str) {
    setup_logging_with_clock(filter, Instant::now)
}

pub fn create_options() -> (Options, Vec<&'static str>) {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
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

pub fn add_middleware_options(opts: &mut Options, _free: &mut [&str]) {
    opts.optopt("", "pcap", "Write a packet capture file", "FILE");
    opts.optopt(
        "",
        "drop-chance",
        "Chance of dropping a packet (%)",
        "CHANCE",
    );
    opts.optopt(
        "",
        "corrupt-chance",
        "Chance of corrupting a packet (%)",
        "CHANCE",
    );
    opts.optopt(
        "",
        "size-limit",
        "Drop packets larger than given size (octets)",
        "SIZE",
    );
    opts.optopt(
        "",
        "tx-rate-limit",
        "Drop packets after transmit rate exceeds given limit \
                                      (packets per interval)",
        "RATE",
    );
    opts.optopt(
        "",
        "rx-rate-limit",
        "Drop packets after transmit rate exceeds given limit \
                                      (packets per interval)",
        "RATE",
    );
    opts.optopt(
        "",
        "shaping-interval",
        "Sets the interval for rate limiting (ms)",
        "RATE",
    );
}

