use wincode::SchemaRead;
use wincode::SchemaWrite;

#[derive(SchemaRead, SchemaWrite, PartialEq, Clone, Copy)]
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

/// Used internally
#[derive(Clone)]
pub struct Partition {
	pub binary_type: BinaryType,
    pub partition_identifier: u32,
    pub partition_name: [u8; 32],
    pub file_name: [u8; 32],
	pub partition_size: u32,
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

pub fn parse_pit(pit_buffer: &Vec<u8>) -> Result<Vec<Partition>, Box<dyn core::error::Error>>{
    let header = wincode::deserialize::<PitHeader>(pit_buffer).unwrap();
	let mut partition_entries = Vec::<Partition>::new();

    if header.magic != 0x12349876 {
        return Err("Wrong magic".into());
    }

    if header.gang_name != *b"COM_TAR2" {
        return Err("Wrong GANG name".into());
    }

    let is_v1 = is_pit_v1(pit_buffer);

    if is_v1 {
        let entries = parse_entries_v1(pit_buffer, header.partition_cnt);       
		
		for entry in entries {
			partition_entries.push(Partition {
				binary_type: entry.binary_type,
				partition_identifier: entry.partition_identifier,
				partition_name: entry.partition_name,
				file_name: entry.file_name,
				partition_size: entry.block_cnt,
			});
		}
    } else {
        let entries = parse_entries_v2(pit_buffer, header.partition_cnt);

		for entry in entries {
			partition_entries.push(Partition {
				binary_type: entry.binary_type,
				partition_identifier: entry.partition_identifier,
				partition_name: entry.partition_name,
				file_name: entry.file_name,
				partition_size: entry.block_cnt,
			});
		}
	}

	Ok(partition_entries)
}

pub fn search_for_partition(partition_name: &str, partition_table: &Vec<Partition>) -> Result<Partition, Box<dyn core::error::Error>> {
	for partition in partition_table {
		if String::from_utf8_lossy(&partition.partition_name).trim_end_matches('\0').to_lowercase() == partition_name.to_lowercase() {
			return Ok(partition.clone());
		}
	}

	Err("Partition not found".into())
}