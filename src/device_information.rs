use wincode::SchemaRead;

#[derive(SchemaRead, PartialEq)]
pub enum DeviceInfoType {
    ModelName,
    Serial,
    Csc,
    CarrierID
}

#[derive(SchemaRead)]
pub struct DeviceInfoHeader {
    pub magic: u32,
    pub item_count: u32,
}

#[derive(SchemaRead)]
pub struct DeviceInfoLocation {
    pub info_type: DeviceInfoType,
    pub offset: u32,
    pub size: u32,
}

#[derive(SchemaRead)]
pub struct DeviceInfoData {
    pub info_type: DeviceInfoType,
    pub size: u32,
    pub data: Vec<u8>,
}

/// Returned and used internally, not by device.
pub struct DeviceInfo {
    pub device_info: Vec<DeviceInfoData>,
}

pub fn parse_device_info_bytes(device_info_buffer: &Vec<u8>) -> Result<DeviceInfo, Box<dyn core::error::Error>> {
    let header = wincode::deserialize::<DeviceInfoHeader>(device_info_buffer).unwrap();
    let mut locations = Vec::<DeviceInfoLocation>::new();
    let mut data_blocks = Vec::<DeviceInfoData>::new();
    let mut position = 8;

    if header.magic != 0x12345678 {
        return Err("Wrong magic".into());
    }

    for n in 0..header.item_count {
        let location = wincode::deserialize::<DeviceInfoLocation>(&device_info_buffer[position..]).unwrap();
        position += 12;
        locations.push(location);
    }

    for location in locations {
        let mut data_buf = Vec::<u8>::new();
        data_buf.extend_from_slice(&device_info_buffer[(location.offset + 8) as usize..(location.offset + 8 + (location.size - 8)) as usize]);

        let deviceinfo_data = DeviceInfoData {
            info_type: location.info_type,
            size: location.size - 8,
            data: data_buf,
        };

        data_blocks.push(deviceinfo_data);
    }

    Ok(DeviceInfo {
        device_info: data_blocks,
    })
}