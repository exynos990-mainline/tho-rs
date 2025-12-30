pub fn is_file_lz4(data: &[u8]) -> bool {
    if data.len() < 4
    {
        return false;
    }
    //return false;
    return u32::from_le_bytes(data[0..4].try_into().expect("Failed to decode first 4 bytes of data")) == 0x184D2204;
}
