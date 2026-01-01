use wincode::SchemaWrite;

use crate::Result;

#[derive(SchemaWrite)]
pub struct SessionPacket {
	pub packet_type: i32,
	pub packet_command: i32,
	pub arg: i32,
}

#[derive(SchemaWrite)]
pub struct CommandPacket {
	pub packet_type: i32,
	pub packet_command: i32,
}

#[derive(SchemaWrite)]
pub struct Session {
	pub protocol_ver: u16,
	pub flash_timeout: i32,
	pub flash_packet_size: i32,
	pub flash_sequence: i32,
}

pub fn packet_to_bytes_pad<T: wincode::Serialize + wincode::SchemaWrite<Src = T>>(
	packet: T,
) -> Result<Vec<u8>> {
	let size = 1024 - size_of::<T>();

	let mut bytes = wincode::serialize(&packet)?;
	bytes.resize(bytes.len() + size, 0);

	Ok(bytes)
}

pub fn check_response(data: &[u8]) -> Result<()> {
	if data[0] != 0xFF {
		return Ok(());
	}

	let error_code = i32::from_le_bytes(data[1..5].try_into()?);
	match error_code {
		-7 => Err(format!("Device returned error code: {} (Ext4)", error_code).into()),
		-6 => Err(format!("Device returned error code: {} (Size)", error_code).into()),
		-5 => Err(format!("Device returned error code: {} (Auth)", error_code).into()),
		-4 => Err(format!("Device returned error code: {} (Write)", error_code).into()),
		-3 => Err(format!("Device returned error code: {} (Erase)", error_code).into()),
		-2 => Err(format!(
			"Device returned error code: {} (Write Protection)",
				  error_code
		)
		.into()),
		_ => Err(format!("Device returned unknown error code: {}", error_code).into()),
	}
}

pub fn parse_session_response(data: &[u8]) -> Result<Session> {
	let protocol_ver = u16::from_le_bytes(data[6..8].try_into()?);
	let flash_timeout;
	let flash_packet_size;
	let flash_sequence;

	match protocol_ver {
		0..=1 => {
			flash_timeout = 30000; // 30s
			flash_packet_size = 131072; // 128KiB
			flash_sequence = 240; // 30MiB
		}
		2.. => {
			flash_timeout = 120000; // 2 Mins
			flash_packet_size = 1048576; // 1MiB
			flash_sequence = 30; // 30MiB
		}
	}

	Ok(Session {
		protocol_ver,
    flash_timeout,
    flash_packet_size,
    flash_sequence,
	})
}
