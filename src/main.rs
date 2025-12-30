use clap::Parser;

mod device;
mod packets;
mod usb;
mod device_information;
mod pit;
mod file_type_detection;

use crate::device::*;
use crate::usb::*;

pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Command (todo: another struct?)
    #[arg(short, long)]
    command: String,
}

fn print_banner() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!("sammy flasher... but in RUST...");
}

fn main() -> Result<()> {
    println!("Hello, world!");

    // let args = Args::parse();
    // we can re-enable this once we actually get something to parse lol

    let mut dev = initialise_usb()?;

    initialize(&mut dev)?;

    Ok(())
}
