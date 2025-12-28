use crate::Result;
use crate::packets::*;
use crate::usb_bulk_read;
use crate::usb_bulk_transfer;

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
    //end_session(device_handle);
    //reboot(device_handle).expect("Failed to reboot device.");

    Ok(())
}
