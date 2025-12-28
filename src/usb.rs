use std::time::Duration;

// Waits for a download mode device and returns a device handle, or None if an error occurs.
pub fn initialise_usb() -> Option<rusb::DeviceHandle<rusb::GlobalContext>>{
	loop {
		for device in rusb::devices().unwrap().iter() {
			let device_desc = device.device_descriptor().unwrap();

			if device_desc.vendor_id() == 0x04E8 && device_desc.product_id() == 0x685D {
				println!("Found download mode device");
				match device.open() {
					Ok(device_handle) => {
						if let Err(e) = device_handle.claim_interface(1) {
							println!("Failed to claim interface: {e:?}");
							return None;
						}
						return Some(device_handle);
					},
					Err(e) => {
						println!("Failed to open device: {e:?}");
						return None;
					}
				}
			}
		}
	}
}

// Does a USB bulk transfer, returns true on success, false on failure.
pub fn usb_bulk_transfer(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>, data: Vec<u8>) -> bool{
	match device_handle.write_bulk(2, &data, Duration::from_secs(5)) {
		Ok(bytes_written) => {
			if bytes_written == data.len() {
				return true;
			} else {
				return false;
			}
		},
		Err(e) => {
			println!("Bulk transfer error: {e:?}");
			return false;
		}
	}
}

// Does a USB bulk read, returns a tuple of (status, bytes).
pub fn usb_bulk_read(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> (bool, Vec<u8>) {
	let mut buffer: Vec<u8> = vec![0u8; 512];

	match device_handle.read_bulk(0x81, &mut buffer, Duration::from_secs(5)) {
		Ok(bytes_read) => {
			if bytes_read > 0 {
				buffer.truncate(bytes_read);
				return (true, buffer);
			} else {
				return (false, buffer);
			}
		},
		Err(e) => {
			println!("Bulk read error: {e:?}");
			return (false, buffer);
		}
	}
}
