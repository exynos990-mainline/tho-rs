use crate::Result;
use crate::packets::*;
use crate::device_information::parse_device_info_bytes;
use crate::device_information::DeviceInfoType;
use crate::device_information::DeviceInfo;
use crate::usb_bulk_read;
use crate::usb_bulk_transfer;

pub fn dump_device_info(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> Result<DeviceInfo> {
    let packet = CommandPacket {
        packet_type: 0x69,
        packet_command: 0x00,
    };
    println!("Requesting device info size...");
    usb_bulk_transfer(device_handle, &packet_to_bytes_pad(packet)?)
        .map_err(|e| format!("Failed to send device info size request: {e:?}"))?;

    let raw_response =
        usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

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
            arg: n as i32
        };

        usb_bulk_transfer(device_handle, &packet_to_bytes_pad(packet)?)
            .map_err(|e| format!("Failed to send device info dump request: {e:?}"))?;

        let raw_response =
            usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

        device_info_buffer[offset as usize .. (offset + 500) as usize].copy_from_slice(&raw_response);
    }

    let packet = CommandPacket {
        packet_type: 0x69,
        packet_command: 0x02,
    };
    println!("Ending dump request.");
    usb_bulk_transfer(device_handle, &packet_to_bytes_pad(packet)?)
        .map_err(|e| format!("Failed to send device info end dump request: {e:?}"))?;

    let raw_response =
        usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

    check_response(&raw_response)?;
    let device_info = parse_device_info_bytes(&device_info_buffer).map_err(|e| format!("Failed to parse device info: {e:?}"))?;
    Ok(device_info)
}

pub fn reboot(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> Result<()> {
    let packet = CommandPacket {
        packet_type: 0x67,
        packet_command: 0x01,
    };
    println!("Sending reboot command");
    usb_bulk_transfer(device_handle, &packet_to_bytes_pad(packet)?)
        .map_err(|e| format!("Failed to send reboot packet: {e:?}"))?;

    let raw_response =
        usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

    check_response(&raw_response)?;

    Ok(())
}

fn handshake(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> Result<()> {
    println!("Handshaking...");
    usb_bulk_transfer(device_handle, b"ODIN")
        .map_err(|e| format!("Failed to send handshake packet: {e:?}"))?;

    let response =
        usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

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

fn begin_session(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> Result<()> {
    let packet = SessionPacket {
        packet_type: 0x64,
        packet_command: 0x00,
        arg: 0x7FFFFFFF,
    };

    println!("Beginning session");
    usb_bulk_transfer(device_handle, &packet_to_bytes_pad(packet)?)
        .map_err(|e| format!("Failed to send begin session packet: {e:?}"))?;

    let raw_response =
        usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

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

        usb_bulk_transfer(device_handle, &packet_to_bytes_pad(packet)?)
            .map_err(|e| format!("Failed to send file part packet: {e:?}"))?;

        let raw_response =
            usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;

        check_response(&raw_response)?;
    }

    Ok(())
}

fn end_session(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> Result<()> {
    let packet = CommandPacket {
        packet_type: 0x67,
        packet_command: 0x00,
    };
    println!("Ending session");
    usb_bulk_transfer(device_handle, &packet_to_bytes_pad(&packet)?)
        .map_err(|e| format!("Failed to send end session packet: {e:?}"))?;

    let raw_response =
        usb_bulk_read(device_handle).map_err(|e| format!("Failed to read response: {e:?}"))?;
    check_response(&raw_response)?;

    Ok(())
}

pub fn initialize(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> Result<()> {
    handshake(device_handle)?;
    begin_session(device_handle)?;
    let devinfo = dump_device_info(device_handle)?;
    for device_info_item in devinfo.device_info {
        if device_info_item.info_type == DeviceInfoType::ModelName {
            println!("Model Name: {}", String::from_utf8_lossy(&device_info_item.data));
        }
    }
    end_session(device_handle);
    reboot(device_handle).expect("Failed to reboot device.");

    Ok(())
}
