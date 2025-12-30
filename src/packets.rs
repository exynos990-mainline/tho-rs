use wincode::SchemaWrite;

use crate::Result;

use crate::pit::BinaryType;

#[derive(SchemaWrite)]
pub struct SessionPacket {
    pub packet_type: u32,
    pub packet_command: u32,
    pub arg: u32,
}

#[derive(SchemaWrite)]
pub struct CommandPacket {
    pub packet_type: u32,
    pub packet_command: u32,
}

#[derive(SchemaWrite)]
pub struct APFlashSequencePacket {
    pub packet_type: u32,
    pub packet_command: u32,
    pub reserved: u32,
    pub sequence_len: u32,
    pub binary_type: BinaryType,
    pub device_type: u32,
    pub partition_identifier: u32,
    pub is_last_sequence: u32,
}

#[derive(SchemaWrite)]
pub struct CPFlashSequencePacket {
    pub packet_type: u32,
    pub packet_command: u32,
    pub reserved: u32,
    pub sequence_len: u32,
    pub binary_type: BinaryType,
    pub device_type: u32,
    pub is_last_sequence: u32,
}

#[derive(SchemaWrite)]
pub struct Session {
    pub compression_supported: bool,
    pub protocol_ver: u16,
    pub flash_timeout: u32,
    pub flash_packet_size: u32,
    pub flash_sequence: u32,
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
    let compression_supported = (u32::from_le_bytes(data[1..5].try_into()?) >> 8) & 0xF0 == 0x80;
    let protocol_ver = u16::from_le_bytes(data[6..8].try_into()?);
    let flash_timeout;
    let flash_packet_size;
    let flash_sequence;

    println!("{}", compression_supported);

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
        compression_supported,
        protocol_ver,
        flash_timeout,
        flash_packet_size,
        flash_sequence,
    })
}
