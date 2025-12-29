use std::time::Duration;

pub type USBResult =
    core::result::Result<rusb::DeviceHandle<rusb::GlobalContext>, Box<dyn core::error::Error>>;
pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

/// Waits for a download mode device and returns a device handle, or None if an error occurs.
pub fn initialise_usb() -> USBResult {
    loop {
        for device in rusb::devices()?.iter() {
            let device_desc = device.device_descriptor()?;

            if device_desc.vendor_id() == 0x04E8 && device_desc.product_id() == 0x685D {
                println!("Found download mode device");

                let handle = device
                    .open()
                    .map_err(|e| format!("Failed to open device: {e:?}"))?;
                handle.claim_interface(1)?;

                return Ok(handle);
            }
        }
    }
}

/// Does a USB bulk transfer, returns true on success, false on failure.
pub fn usb_bulk_transfer(
    device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    data: &[u8],
) -> Result<()> {
    match device_handle.write_bulk(2, &data, Duration::from_secs(5)) {
        Ok(bytes_written) => {
            if bytes_written == data.len() {
                Ok(())
            } else {
                Err("bytes written != data.len()".into())
            }
        }
        Err(e) => Err(format!("Bulk transfer error: {e:?}").into()),
    }
}

/// Does a USB bulk read, returns a tuple of (status, bytes).
pub fn usb_bulk_read(
    device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![0u8; 512];

    match device_handle.read_bulk(0x81, &mut buffer, Duration::from_secs(5)) {
        Ok(bytes_read) => {
            if bytes_read > 0 {
                buffer.truncate(bytes_read);
                Ok(buffer)
            } else {
                Err("bytes_read <= 0".into())
            }
        }
        Err(e) => Err(format!("Bulk read error: {e:?}").into()),
    }
}

/// Does a USB bulk read with a timeout param, returns a tuple of (status, bytes).
pub fn usb_bulk_read_timeout(
    device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    timeout: Duration
) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![0u8; 512];

    match device_handle.read_bulk(0x81, &mut buffer, timeout) {
        Ok(bytes_read) => {
            if bytes_read > 0 {
                buffer.truncate(bytes_read);
                Ok(buffer)
            } else {
                Err("bytes_read <= 0".into())
            }
        }
        Err(e) => Err(format!("Bulk read error: {e:?}").into()),
    }
}
