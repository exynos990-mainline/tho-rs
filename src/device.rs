pub fn reboot(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> bool {
	println!("Not implemented.");
	return false;
}

fn handshake(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> bool {
	println!("Not implemented.");
	return false;
}

fn beginSession(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> bool {
	println!("Not implemented.");
	return false;
}

pub fn initialize(device_handle: &mut rusb::DeviceHandle<rusb::GlobalContext>) -> bool {
	handshake(device_handle);
	beginSession(device_handle);

	return false;
}
