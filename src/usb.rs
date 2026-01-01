use std::time::Duration;

pub struct USBDevice {
	handle: rusb::DeviceHandle<rusb::GlobalContext>,
	in_ep: u8,
	out_ep: u8,
}

pub type USBResult =
	core::result::Result<USBDevice, Box<dyn core::error::Error>>;
pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

/// Waits for a download mode device and returns a device handle, or None if an error occurs.
pub fn initialise_usb() -> USBResult {
	loop {
		for device in rusb::devices()?.iter() {
			let device_desc = device.device_descriptor()?;

			if device_desc.vendor_id() == 0x04E8 && device_desc.product_id() == 0x685D {
				let mut interface_num = 0;
				let mut in_ep = 0;
				let mut out_ep = 0;
				println!("Found download mode device");

				for config_num in 0..device_desc.num_configurations() {
					let config_desc = device.config_descriptor(config_num)?;

					for interface in config_desc.interfaces() {
						for interface_desc in interface.descriptors() {
							interface_num = interface_desc.interface_number();

							// CDC interface class
							if interface_desc.class_code() == 0x0A {
								for endpoint in interface_desc.endpoint_descriptors() {
									if endpoint.direction() == rusb::Direction::In {
										in_ep = endpoint.address();
									} else {
										out_ep = endpoint.address();
									}
								}
							}
						}
					}
				}

				let handle = device
					.open()
					.map_err(|e| format!("Failed to open device: {e:?}"))?;
				handle.claim_interface(interface_num)?;

				return Ok(USBDevice {
					handle,
					in_ep,
					out_ep,
				});
			}
		}
	}
}

/// Does a USB bulk transfer, returns true on success, false on failure.
pub fn usb_bulk_transfer(
	device: &mut USBDevice,
	data: &[u8],
) -> Result<()> {
	let device_handle = &device.handle;

	match device_handle.write_bulk(device.out_ep, &data, Duration::from_secs(5)) {
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

/// Does a USB bulk read with a timeout param, returns a tuple of (status, bytes).
pub fn usb_bulk_read_timeout(
	device: &mut USBDevice,
	timeout: Duration
) -> Result<Vec<u8>> {
	let device_handle = &device.handle;
	let mut buffer: Vec<u8> = vec![0u8; 512];

	match device_handle.read_bulk(device.in_ep, &mut buffer, timeout) {
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

/// Does a USB bulk read, returns a tuple of (status, bytes).
pub fn usb_bulk_read(
	device: &mut USBDevice,
) -> Result<Vec<u8>> {
	usb_bulk_read_timeout(device, Duration::from_secs(5))
}