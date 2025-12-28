use clap::Parser;

mod device;
mod usb;
use crate::usb::*;
use crate::device::*;

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


fn main() {
	println!("Hello, world!");

	// let args = Args::parse();
	// we can re-enable this once we actually get something to parse lol

	let dev = initialise_usb().expect("Something bad happened :(");


	initialize(dev);
}
