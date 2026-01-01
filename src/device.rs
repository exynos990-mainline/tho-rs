use crate::Result;
use crate::packets::*;
use crate::device_information::parse_device_info_bytes;
use crate::device_information::DeviceInfoType;
use crate::device_information::DeviceInfoData;
use crate::pit::Partition;
use crate::pit::BinaryType;
use crate::pit::parse_pit;
use crate::pit::search_for_partition;
use crate::file_type_detection::is_file_lz4;
use crate::USBDevice;
use crate::usb_bulk_read;
use crate::usb_bulk_read_timeout;
use crate::usb_bulk_transfer;
use std::fs;
use std::time::Duration;

pub fn dump_device_info(device: &mut USBDevice) -> Result<Vec<DeviceInfoData>> {
	let packet = CommandPacket {
		packet_type: 0x69,
		packet_command: 0x00,
	};

	println!("Requesting device info size...");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send device info size request: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;

	let device_info_size = u32::from_le_bytes(raw_response[4..8].try_into()?);
	let device_info_blocks = device_info_size / 500;
	println!("Device info size: {device_info_size} bytes, {device_info_blocks} blocks.");

	let mut device_info_buffer: Vec<u8> = vec![0u8; device_info_size as usize];
	println!("Dumping blocks");

	for n in 0..device_info_blocks {
		let offset = n * 500;
		let packet = SessionPacket {
			packet_type: 0x69,
			packet_command: 0x01,
			arg: n
		};

		usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
			.map_err(|e| format!("Failed to send device info dump request: {e:?}"))?;

		let raw_response =
			usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

		device_info_buffer[offset as usize .. (offset + 500) as usize].copy_from_slice(&raw_response);
	}

	let packet = CommandPacket {
		packet_type: 0x69,
		packet_command: 0x02,
	};

	println!("Ending dump request.");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send device info end dump request: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;
	let device_info = parse_device_info_bytes(&device_info_buffer).map_err(|e| format!("Failed to parse device info: {e:?}"))?;
	Ok(device_info)
}

pub fn dump_pit(device: &mut USBDevice) -> Result<Vec<Partition>> {
	let packet = CommandPacket {
		packet_type: 0x65,
		packet_command: 0x01,
	};

	println!("Requesting PIT size...");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send PIT size request: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;

	let pit_size = u32::from_le_bytes(raw_response[4..8].try_into()?);
	let pit_blocks = pit_size / 500;
	println!("PIT size: {pit_size} bytes, {pit_blocks} blocks.");

	let mut pit_buffer: Vec<u8> = vec![0u8; pit_size as usize];
	println!("Dumping blocks");

	for n in 0..pit_blocks {
		let offset = n * 500;
		let packet = SessionPacket {
			packet_type: 0x65,
			packet_command: 0x02,
			arg: n
		};

		usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
			.map_err(|e| format!("Failed to send PIT dump request: {e:?}"))?;

		let raw_response =
			usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

		pit_buffer[offset as usize .. (offset + 500) as usize].copy_from_slice(&raw_response);
	}

	let packet = CommandPacket {
		packet_type: 0x65,
		packet_command: 0x03,
	};

	println!("Ending dump request.");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send PIT end dump request: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;
	let partition_table = parse_pit(&pit_buffer)?;
	Ok(partition_table)
}

pub fn reboot(device: &mut USBDevice) -> Result<()> {
	let packet = CommandPacket {
		packet_type: 0x67,
		packet_command: 0x01,
	};

	println!("Sending reboot command");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send reboot packet: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;

	Ok(())
}

fn handshake(device: &mut USBDevice) -> Result<()> {
	println!("Handshaking...");
	usb_bulk_transfer(device, b"ODIN")
		.map_err(|e| format!("Failed to send handshake packet: {e:?}"))?;

	let response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	if response != b"LOKE" {
		println!(
			"Handshake failed: expected LOKE, got {}",
			String::from_utf8_lossy(&response)
		);

		return Err("Handshake failed.".into());
	}

	println!("Hand shook");

	Ok(())
}

fn flash_device(device: &mut USBDevice, session: Session, data: Vec<u8>, partition: &Partition) -> Result<()> {
	let data_length = data.len();
	let sequence_size = session.flash_packet_size * session.flash_sequence;
	let is_lz4 = is_file_lz4(&data);

	if is_lz4 {
		println!("Detected LZ4 compressed image");
		println!("Compression supported by device: {}", session.compression_supported);

		if session.compression_supported == false {
			println!("LZ4 file being flash under a protocol that doesn't support direct LZ4 flashes.");
			return Err("LZ4 file being flash under a protocol that doesn't support direct LZ4 flashes.".into()); // TODO: handle nicer
		}
	}

	let packet = CommandPacket {
		packet_type: 0x66,
		packet_command: if is_lz4 {0x05} else {0x00},
	};

	println!("Sending flash request command");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send flash request packet: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;

	for (seq_index, sequence) in data.chunks(sequence_size as usize).enumerate() {
		let real_size = sequence.len();
		let aligned_size = real_size.next_multiple_of(session.flash_packet_size as usize);
		let is_last_sequence = seq_index + 1 == data_length.div_ceil(sequence_size as usize);

		let packet = SessionPacket {
			packet_type: 0x66,
			packet_command: if is_lz4 {0x02} else {0x06},
			arg: aligned_size as u32,
		};

		println!("Sending flash sequence request command");
		usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
			.map_err(|e| format!("Failed to send flash sequence request packet: {e:?}"))?;

		let raw_response =
			usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

		check_response(&raw_response)?;

		let chunks = sequence.chunks_exact(session.flash_packet_size as usize);

		for (chunk_index, chunk) in chunks.clone().enumerate() {
			println!("Sending file part {chunk_index}");
			usb_bulk_transfer(device, chunk)
				.map_err(|e| format!("Failed to send flash sequence request packet: {e:?}"))?;

			let raw_response =
				usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

			check_response(&raw_response)?;

			let device_chunk_index = u32::from_le_bytes(raw_response[4..8].try_into().unwrap());
			if device_chunk_index != chunk_index as u32 {
				return Err(format!("Expected packet index {chunk_index}, bootloader returned {device_chunk_index}").into());
			}
		}

		let remainder = chunks.remainder();
		if !remainder.is_empty() {
			let chunk_index = chunks.len();
			let mut padded = vec![0u8; session.flash_packet_size as usize];
			padded[..remainder.len()].copy_from_slice(remainder);

			println!("Sending last file part {chunk_index}");

			usb_bulk_transfer(device, &padded)
				.map_err(|e| format!("Failed to send flash sequence request packet: {e:?}"))?;

			let raw_response =
				usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

			check_response(&raw_response)?;

			let device_chunk_index = u32::from_le_bytes(raw_response[4..8].try_into().unwrap());
			if device_chunk_index != chunk_index as u32 {
				return Err(format!("Expected packet index {chunk_index}, bootloader returned {device_chunk_index}").into());
			}
		}

		if partition.binary_type == BinaryType::Cp {
			let packet = CPFlashSequencePacket {
				packet_type: 0x66,
				packet_command: if is_lz4 {0x07} else {0x03},
				reserved: 0x01,
				sequence_len: real_size as u32,
				binary_type: partition.binary_type,
				device_type: partition.device_type,
				is_last_sequence: is_last_sequence as u32
			};

				usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
				.map_err(|e| format!("Failed to send flash sequence end request packet (CP): {e:?}"))?;

			let raw_response =
				usb_bulk_read_timeout(device, Duration::from_millis(session.flash_timeout as u64)).map_err(|e| format!("Failed to read response (CP): {e:?}"))?;

			check_response(&raw_response)?;
		} else {
			let packet = APFlashSequencePacket {
				packet_type: 0x66,
				packet_command: if is_lz4 {0x07} else {0x03},
				reserved: 0x00,
				sequence_len: real_size as u32,
				binary_type: partition.binary_type,
				device_type: partition.device_type,
				partition_identifier: partition.partition_identifier,
				is_last_sequence: is_last_sequence as u32
			};

			usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
				.map_err(|e| format!("Failed to send flash sequence end request packet (AP): {e:?}"))?;

			let raw_response =
				usb_bulk_read_timeout(device, Duration::from_millis(session.flash_timeout as u64)).map_err(|e| format!("Failed to read response (AP): {e:?}"))?;

			check_response(&raw_response)?;
		}
	}

	Ok(())
}

fn begin_session(device: &mut USBDevice) -> Result<Session> {
	let packet = SessionPacket {
		packet_type: 0x64,
		packet_command: 0x00,
		arg: 0x7FFFFFFF,
	};

	println!("Beginning session");
	usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
		.map_err(|e| format!("Failed to send begin session packet: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;
	let session = parse_session_response(&raw_response)?;

	println!("Session protocol version: {}", session.protocol_ver);
	println!("Flash timeout: {}", session.flash_timeout);
	println!("Flash packet size: {}", session.flash_packet_size);
	println!("Flash sequence: {}", session.flash_sequence);

	if session.protocol_ver > 1 {
		let packet = SessionPacket {
			packet_type: 0x64,
			packet_command: 0x05,
			arg: session.flash_packet_size,
		};

		println!("Sending file part size of {}", session.flash_packet_size);

		usb_bulk_transfer(device, &packet_to_bytes_pad(packet)?)
			.map_err(|e| format!("Failed to send file part packet: {e:?}"))?;

		let raw_response =
			usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

		check_response(&raw_response)?;
	}

	Ok(session)
}

fn end_session(device: &mut USBDevice) -> Result<()> {
	let packet = CommandPacket {
		packet_type: 0x67,
		packet_command: 0x00,
	};

    println!("Ending session");
	usb_bulk_transfer(device, &packet_to_bytes_pad(&packet)?)
		.map_err(|e| format!("Failed to send end session packet: {e:?}"))?;

	let raw_response =
		usb_bulk_read(device).map_err(|e| format!("Failed to read response: {e:?}"))?;

	check_response(&raw_response)?;

	Ok(())
}

pub fn initialize(device: &mut USBDevice) -> Result<()> {
	handshake(device)?;
	let session = begin_session(device)?;

	for device_info_item in dump_device_info(device)? {
		if device_info_item.info_type == DeviceInfoType::ModelName {
			println!("Model Name: {}", String::from_utf8_lossy(&device_info_item.data));
		}
	}

	let partitions = dump_pit(device)?;

	println!("Flashing lk3rd v1.0");

	let lk3rd = fs::read("lk3rd-x1s.img")?;
	let boot = search_for_partition("BOOT", &partitions)?;

	println!("Available Partitions: ");
	for partition in partitions {
	    println!("Name: {} Size (Blocks): {}, Identifier: {}, Type: {}, Flash File Name: {}", String::from_utf8_lossy(&partition.partition_name), partition.partition_size, partition.partition_identifier, partition.binary_type as u32, String::from_utf8_lossy(&partition.file_name));
	}

	println!("found boot");

	flash_device(device, session, lk3rd, &boot);
	end_session(device);
	reboot(device).expect("Failed to reboot device.");

	Ok(())
}
