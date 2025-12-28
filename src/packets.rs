use wincode::SchemaWrite;

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

pub fn session_packet_to_bytes(packet: &SessionPacket) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&packet.packet_type.to_le_bytes());
    bytes.extend_from_slice(&packet.packet_command.to_le_bytes());
    bytes.extend_from_slice(&packet.arg.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 1012]);

    return bytes;
}

pub fn command_packet_to_bytes(packet: &CommandPacket) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&packet.packet_type.to_le_bytes());
    bytes.extend_from_slice(&packet.packet_command.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 1016]);

    return bytes;
}

pub fn check_response(data: &[u8]) -> Result<(), Box<dyn core::error::Error>> {
    if data[0] != 0xFF {
        return Ok(());
    }

    let error_code = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    match error_code {
        -7 => return Err(format!("Device returned error code: {} (Ext4)", error_code).into()),
        -6 => return Err(format!("Device returned error code: {} (Size)", error_code).into()),
        -5 => return Err(format!("Device returned error code: {} (Auth)", error_code).into()),
        -4 => return Err(format!("Device returned error code: {} (Write)", error_code).into()),
        -3 => return Err(format!("Device returned error code: {} (Erase)", error_code).into()),
        -2 => return Err(format!("Device returned error code: {} (Write Protection)", error_code).into()),
        _ => return Err(format!("Device returned unknown error code: {}", error_code).into()),
    }
}

pub fn parse_session_response(data: &[u8]) -> Session {
    let protocol_ver = u16::from_le_bytes([data[6], data[7]]);
    let flash_timeout;
    let flash_packet_size;
    let flash_sequence;

    match protocol_ver {
        0..=1 => {
            flash_timeout = 30000; // 30s
            flash_packet_size = 131072; // 128KiB
            flash_sequence = 240; // 30MiB
        },
        2.. => {
            flash_timeout = 120000; // 2 Mins
            flash_packet_size = 1048576; // 1MiB
            flash_sequence = 30; // 30MiB
        }
    }

    return Session {
        protocol_ver,
        flash_timeout,
        flash_packet_size,
        flash_sequence,
    }
}