use wincode::SchemaRead;
use wincode::SchemaWrite;

#[derive(SchemaRead, SchemaWrite, PartialEq)]
#[repr(u32)]
pub enum BinaryType {
    Ap,
    Cp
}

#[derive(SchemaRead, PartialEq)]
pub enum DeviceTypeV1 {
    OneNand,
    Nand,
    MoviNand
}

#[derive(SchemaRead, PartialEq)]
pub enum DeviceTypeV2 {
    OneNand,
    Nand,
    Emmc,
    Spi,
    Ide,
    NandX16,
    Unknown1,
    Unknown2,
    Unknown3,
    Ufs
}

#[derive(SchemaRead, PartialEq)]
pub enum Attributes {
    ReadOnly,
    ReadWrite,
    Stl
}

#[derive(SchemaRead, PartialEq)]
pub enum UpdateAttributes {
    None,
    Fota,
    Secure,
    FotaSecure
}

#[derive(SchemaRead, PartialEq)]
pub enum PartitionType {
    None,
    Bct,
    Bootloader,
    PartitionTable,
    NvData,
    Data,
    Mbr,
    Ebr,
    Gp1,
    Gp1_2
}

#[derive(SchemaRead, PartialEq)]
pub enum FileSystem {
    None,
    Basic,
    Enhanced,
    Ext2,
    Yaffs2,
    Ext4
}

#[derive(SchemaRead)]
pub struct PitHeader {
    pub magic: u32,
    pub partition_cnt: u32,
    pub gang_name: [u8; 8],
    pub project_name: [u8; 8],
    pub reserved: u32,
}

#[derive(SchemaRead)]
pub struct PitEntryV1 {
    pub binary_type: BinaryType,
    pub device_type: DeviceTypeV1,
    pub partition_identifier: u32,
    pub attributes: Attributes,
    pub update_attributes: UpdateAttributes,
    pub block_size: u32,
    pub block_cnt: u32,
    pub file_offset: u32,
    pub file_size: u32,
    pub partition_name: [u8; 32],
    pub file_name: [u8; 32],
    pub delta: [u8; 32],
}

#[derive(SchemaRead)]
pub struct PitEntryV2 {
    pub binary_type: BinaryType,
    pub device_type: DeviceTypeV2,
    pub partition_identifier: u32,
    pub partition_type: PartitionType,
    pub file_system: FileSystem,
    pub start_block: u32,
    pub block_cnt: u32,
    pub lun: u32,
    pub reserved: u32,
    pub partition_name: [u8; 32],
    pub file_name: [u8; 32],
    pub delta: [u8; 32],
}

/// Used internally, someone please polish
pub struct Pit {
    pub is_v1: bool,
    pub entries_v1: Vec<PitEntryV1>,
    pub entries_v2: Vec<PitEntryV2>,
}

/// Check if block info is equal between 2 partitions, V1 has it hardcoded to a constant blocksize, whereas V2 doesn't as it uses it as a partition start offset.
fn is_pit_v1(pit_buffer: &Vec<u8>) -> bool {
    return u32::from_le_bytes(pit_buffer[840..844].try_into().expect("Failed to decode block info")) == u32::from_le_bytes(pit_buffer[972..976].try_into().expect("Failed to decode block info"));
}

fn parse_entries_v1(pit_buffer: &Vec<u8>, partition_cnt: u32) -> Vec<PitEntryV1>{
    let mut position = 28;
    let mut entries = Vec::<PitEntryV1>::new();

    for _n in 0..partition_cnt {
        let entry = wincode::deserialize::<PitEntryV1>(&pit_buffer[position..]).unwrap();
        entries.push(entry);
        position += 132
    }

    return entries;
}

fn parse_entries_v2(pit_buffer: &Vec<u8>, partition_cnt: u32) -> Vec<PitEntryV2> {
    let mut position = 28;
    let mut entries = Vec::<PitEntryV2>::new();

    for _n in 0..partition_cnt {
        let entry = wincode::deserialize::<PitEntryV2>(&pit_buffer[position..]).unwrap();
        entries.push(entry);
        position += 132
    }

    return entries;
}

pub fn parse_pit(pit_buffer: &Vec<u8>) -> Result<Pit, Box<dyn core::error::Error>>{
    let header = wincode::deserialize::<PitHeader>(pit_buffer).unwrap();
    let mut entries_v1 = Vec::<PitEntryV1>::new();
    let mut entries_v2 = Vec::<PitEntryV2>::new();

    if header.magic != 0x12349876 {
        return Err("Wrong magic".into());
    }

    if header.gang_name != *b"COM_TAR2" {
        return Err("Wrong GANG name".into());
    }

    let is_v1 = is_pit_v1(pit_buffer);

    if is_v1 {
        entries_v1 = parse_entries_v1(pit_buffer, header.partition_cnt);
    } else {
        entries_v2 = parse_entries_v2(pit_buffer, header.partition_cnt);
    }

    Ok(Pit{
        is_v1: is_v1,
        entries_v1: entries_v1,
        entries_v2: entries_v2,
    })
}