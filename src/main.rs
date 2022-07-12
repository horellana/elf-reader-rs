use std::fs;
use std::io;
use std::path::Path;
use std::process;

use std::fmt;

extern crate endianness;
use clap::Parser;
use endianness::*;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CommandLineArguments {
    #[clap(value_parser)]
    file_path: String,

    #[clap(short = 'h', long, help = "Display the ELF file header")]
    file_headers: bool,
}

impl CommandLineArguments {
    fn should_load_file(&self) -> bool {
        if self.file_headers {
            true
        } else {
            false
        }
    }
}

#[derive(Debug, PartialEq)]
enum EClass {
    X32 = 0x01,
    X64 = 0x02,
}

impl fmt::Display for EClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EClass::X32 => write!(f, "ELF32"),
            EClass::X64 => write!(f, "ELF64"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum EData {
    LittleEndian = 0x01,
    BigEndian = 0x02,
}

impl fmt::Display for EData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EData::LittleEndian => write!(f, "little endian"),
            EData::BigEndian => write!(f, "big endian"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ELFISA {
    NoSpecificInstructionSet = 0x00,
    ATTWE32100 = 0x01,
    SPARC = 0x02,
    X86 = 0x03,
    AMD64 = 0x3E,
}

impl fmt::Display for ELFISA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ELFISA::AMD64 => write!(f, "Advanced Micro Devices X86-64"),
            _ => write!(f, "Unknown ISA"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ELFVersion {
    EVNone = 0,
    EVCurrent = 1,
    EVUnknown = 2,
}

impl fmt::Display for ELFVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ELFVersion::EVCurrent => write!(f, "1 (Current)"),
            _ => write!(f, "0"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ELFError {
    InvalidSectionHeaderEntryCount,
    InvalidSectionHeaderTableSize,
    InvalidProgramHeaderEntriesNumber,
    InvalidProgramHeaderTableSize,
    InvalidHeaderSize,
    InvalidEFlags,
    InvalidFile,
    InvalidIsa,
    InvalidOsAbi,
    InvalidAbiVersion,
    InvalidPadding,
    InvalidObjectFileType,
    InvalidVersion,
    InvalidEntryPoint,
    InvalidSectionHeaderStart,
    InvalidProgramHeaderStart,
}

#[derive(PartialEq, Debug)]
enum ELFPadding {}

#[derive(PartialEq, Debug)]
enum ELFABIVersion {
    Unspecified,
}

impl fmt::Display for ELFABIVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ELFABIVersion::Unspecified => write!(f, "0"),
            _ => write!(f, "Unknown ABI Version"),
        }
    }
}

#[derive(PartialEq, Debug)]
enum ELFObjectFileType {
    ETNONE = 0x00,
    ETREL = 0x01,
    ETEXEC = 0x02,
    ETDYN = 0x03,
    ETCORE = 0x04,
    ETLOOS = 0xFE00,
    ETHIOS = 0xFEFF,
    ETLOPROC = 0xFF00,
    ETHIPROC = 0xFFFF,
}

impl fmt::Display for ELFObjectFileType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ELFObjectFileType::ETNONE => write!(f, "None"),
            ELFObjectFileType::ETDYN => write!(f, "DYN (Position-Independent Executable file)"),
            _ => write!(f, "Unknown"),
        }
    }
}

#[derive(PartialEq, Debug)]
enum ELFABI {
    SystemV = 0x00,
    HpUx = 0x01,
    NetBsd = 0x02,
    Linux = 0x03,
    GnuHurd = 0x04,
    Solaris = 0x06,
    Aix = 0x07,
    Irix = 0x08,
    FreeBsd = 0x09,
    Tru64 = 0x0a,
    NovellModesto = 0x0b,
    OpenBsd = 0x0c,
    OpenVms = 0x0d,
    NonstopKernel = 0x0e,
    Aros = 0x0f,
    FenixOs = 0x10,
    NuxiCloudAbi = 0x11,
    StratusTechnologiesOpenVos = 0x12,
}

impl fmt::Display for ELFABI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ELFABI::SystemV => write!(f, "Unix - System V"),
            _ => write!(f, "Unknown"),
        }
    }
}

fn to_number(bytes: &[u8], start: usize, end: usize, endianness: endianness::ByteOrder) -> Option<u64> {
    if bytes.len() < end - 1 {
        eprintln!("Invalid bytes length");
        return None;
    }

    let dv = end - start;
    let range = &bytes[start..end];

    let n: u64 = if dv == 2 {
        read_u16(range, endianness).ok()? as u64
    } else if dv == 4 {
        read_u32(range, endianness).ok()? as u64
    } else {
        read_u64(range, endianness).ok()?
    };

    Some(n)
}

#[derive(Debug, PartialEq)]
struct ELFHeaders {
    e_class: EClass,
    e_data: EData,
    e_version: ELFVersion,
    e_osabi: ELFABI,
    e_abiversion: ELFABIVersion,
    e_pad: [u8; 7],
    e_type: ELFObjectFileType,
    e_machine: ELFISA,
    e_entry: u16,
    e_phoff: u16,
    e_shoff: u16,
    e_flags: u16,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u32,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[derive(Debug, PartialEq)]
struct ELFParser<'a> {
    bytes: &'a Vec<u8>,
}

impl ELFHeaders {
    fn from_bytes(bytes: &Vec<u8>) -> Result<ELFHeaders, ELFError> {
        let parser = ELFParser { bytes: &bytes };

        let e_class = if parser.is_64bit() {
            EClass::X64
        } else {
            EClass::X32
        };

        let e_data = if parser.is_big_endian() {
            EData::BigEndian
        } else {
            EData::LittleEndian
        };

        let e_version = parser.get_e_version()?;
        let e_osabi = parser.get_os_abi()?;
        let e_abiversion = parser.get_abi_version()?;
        let e_type = parser.get_object_file_type()?;
        let e_machine = parser.get_machine_instruction_set()?;
        let e_entry = parser.get_entry_point()?;
        let e_phoff = parser.get_program_header_start()?;
        let e_shoff = parser.get_section_header_start()?;
        let e_flags = parser.get_e_flags()?;
        let e_ehsize = parser.get_header_size()?;
        let e_phentsize = parser.get_program_header_table_size()?;
        let e_phnum = parser.get_program_header_entries_number()?;
        let e_shentsize = parser.get_section_header_size()?;
        let e_shnum = parser.get_section_header_entry_count()?;
        let e_shstrndx = parser.get_section_header_table_index()?;
        let e_pad = [0_u8; 7];

        let elf_headers = ELFHeaders {
            e_class,
            e_data,
            e_version,
            e_osabi,
            e_abiversion,
            e_type,
            e_machine,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
            e_pad,
        };

        Ok(elf_headers)
    }
}

impl<'a> ELFParser<'a> {
    fn get_endianness(&self) -> endianness::ByteOrder {
        if self.is_big_endian() {
            ByteOrder::BigEndian
        }
        else {
            ByteOrder::LittleEndian
        }
    }

    fn get_section_header_table_index(&self) -> Result<u16, ELFError> {
        let n = to_number(self.bytes, 62, 64, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidSectionHeaderEntryCount),
        }
    }

    fn get_section_header_entry_count(&self) -> Result<u16, ELFError> {
        let n = to_number(self.bytes, 60, 62, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidSectionHeaderEntryCount),
        }
    }

    fn get_section_header_size(&self) -> Result<u16, ELFError> {
        let n = to_number(self.bytes, 58, 60, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidSectionHeaderTableSize),
        }
    }

    fn get_program_header_entries_number(&self) -> Result<u32, ELFError> {
        let n = to_number(self.bytes, 56, 58, self.get_endianness());

        match n {
            Some(n) => Ok(n as u32),
            None => Err(ELFError::InvalidProgramHeaderEntriesNumber),
        }
    }

    fn get_program_header_table_size(&self) -> Result<u16, ELFError> {
        let start = if self.is_64bit() { 54 } else { 43 };
        let n = to_number(self.bytes, start, start + 2, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidProgramHeaderTableSize),
        }
    }

    fn get_header_size(&self) -> Result<u16, ELFError> {
        let start = if self.is_64bit() { 52 } else { 41 };
        let n = to_number(self.bytes, start, start + 2, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidHeaderSize),
        }
    }

    fn get_e_flags(&self) -> Result<u16, ELFError> {
        let start = if self.is_64bit() { 48 } else { 37 };
        let n = to_number(self.bytes, start, start + 2, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidEFlags),
        }
    }

    fn get_section_header_start(&self) -> Result<u16, ELFError> {
        let start = if self.is_64bit() { 40 } else { 33 };
        let size = if self.is_64bit() { 8 } else { 4 };
        let n = to_number(self.bytes, start, start + size, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidSectionHeaderStart),
        }
    }

    fn get_program_header_start(&self) -> Result<u16, ELFError> {
        let start = if self.is_64bit() { 32 } else { 28 };
        let size = if self.is_64bit() { 8 } else { 4 };
        let n = to_number(self.bytes, start, start + size, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidProgramHeaderStart),
        }
    }

    fn get_machine_instruction_set(&self) -> Result<ELFISA, ELFError> {
        match (self.bytes[18], self.bytes[19]) {
            (0x3E, 0x00) => Ok(ELFISA::AMD64),
            _ => Err(ELFError::InvalidIsa),
        }
    }

    fn get_entry_point(&self) -> Result<u16, ELFError> {
        let start = 24;
        let size = if self.is_64bit() { 8 } else { 4 };

        let n = to_number(self.bytes, start, start + size, self.get_endianness());

        match n {
            Some(n) => Ok(n as u16),
            None => Err(ELFError::InvalidEntryPoint),
        }
    }

    fn get_e_version(&self) -> Result<ELFVersion, ELFError> {
        if self.bytes.len() < 23 {
            Err(ELFError::InvalidVersion)
        } else {
            match self.bytes[22] {
                0x00 => Ok(ELFVersion::EVNone),
                0x01 => Ok(ELFVersion::EVCurrent),
                _ => Ok(ELFVersion::EVUnknown),
            }
        }
    }

    fn get_object_file_type(&self) -> Result<ELFObjectFileType, ELFError> {
        if self.bytes.len() < 18 {
            Err(ELFError::InvalidObjectFileType)
        } else {
            match (self.bytes[16], self.bytes[17]) {
                (0x00, 0x00) => Ok(ELFObjectFileType::ETNONE),
                (0x01, 0x00) => Ok(ELFObjectFileType::ETREL),
                (0x02, 0x00) => Ok(ELFObjectFileType::ETEXEC),
                (0x03, 0x00) => Ok(ELFObjectFileType::ETDYN),
                (0x04, 0x00) => Ok(ELFObjectFileType::ETCORE),
                _ => Err(ELFError::InvalidObjectFileType),
            }
        }
    }

    fn get_padding(&self) -> Result<&[u8], ELFError> {
        if self.bytes.len() >= 16 {
            Ok(&(self.bytes)[9..16])
        } else {
            Err(ELFError::InvalidPadding)
        }
    }

    fn get_abi_version(&self) -> Result<ELFABIVersion, ELFError> {
        match self.bytes[8] {
            0 => Ok(ELFABIVersion::Unspecified),
            _ => Err(ELFError::InvalidAbiVersion),
        }
    }

    fn get_os_abi(&self) -> Result<ELFABI, ELFError> {
        if self.bytes.len() < 8 {
            Err(ELFError::InvalidOsAbi)
        } else {
            match self.bytes[7] {
                0x00 => Ok(ELFABI::SystemV),
                0x01 => Ok(ELFABI::HpUx),
                0x02 => Ok(ELFABI::NetBsd),
                0x03 => Ok(ELFABI::Linux),
                0x04 => Ok(ELFABI::GnuHurd),
                0x06 => Ok(ELFABI::Solaris),
                0x07 => Ok(ELFABI::Aix),
                0x08 => Ok(ELFABI::Irix),
                0x09 => Ok(ELFABI::FreeBsd),
                0x0a => Ok(ELFABI::Tru64),
                0x0b => Ok(ELFABI::NovellModesto),
                0x0c => Ok(ELFABI::OpenBsd),
                0x0d => Ok(ELFABI::OpenVms),
                0x0e => Ok(ELFABI::NonstopKernel),
                0x0f => Ok(ELFABI::Aros),
                0x10 => Ok(ELFABI::FenixOs),
                0x11 => Ok(ELFABI::NuxiCloudAbi),
                0x12 => Ok(ELFABI::StratusTechnologiesOpenVos),
                _ => Err(ELFError::InvalidOsAbi),
            }
        }
    }

    fn get_version(&self) -> Result<ELFVersion, ELFError> {
        if self.bytes.len() < 7 {
            Err(ELFError::InvalidVersion)
        } else {
            match self.bytes[6] {
                0 => Ok(ELFVersion::EVNone),
                1 => Ok(ELFVersion::EVCurrent),
                _ => Ok(ELFVersion::EVUnknown),
            }
        }
    }

    fn is_little_endian(&self) -> bool {
        self.bytes[5] == 1
    }

    fn is_big_endian(&self) -> bool {
        self.bytes[5] == 2
    }

    fn is_64bit(&self) -> bool {
        self.bytes[4] == 2
    }

    fn is_32bit(&self) -> bool {
        self.bytes[4] == 1
    }

    fn is_elf(&self) -> bool {
        self.bytes[0] == 0x7F
            && self.bytes[1] == 0x45
            && self.bytes[2] == 0x4C
            && self.bytes[3] == 0x46
    }
}

fn show_headers(elf: ELFHeaders) {
    println!("ELF Header:");
    println!(" Magic: ");
    println!(" Class: {}", elf.e_class);
    println!(" Data: {}", elf.e_data);
    println!(" Version: {}", elf.e_version);
    println!(" OS/ABI: {}", elf.e_osabi);
    println!(" ABI Version: {}", elf.e_abiversion);
    println!(" Type: {}", elf.e_type);
    println!(" Machine: {}", elf.e_machine);
    println!(" Entry point address: {:#01X}", elf.e_entry);
    println!(
        " Start of program headers: {} (bytes into file)",
        elf.e_phoff
    );
    println!(
        " Start of section headers: {} (bytes into file)",
        elf.e_shoff
    );
    println!(" Flags: {}", elf.e_flags);
    println!(" Size of this header: {} (bytes)", elf.e_ehsize);
    println!(" Size of program headers: {} (bytes)", elf.e_phentsize);
    println!(" Number of program headers: {}", elf.e_phnum);
    println!(" Size of section headers: {} (bytes)", elf.e_shentsize);
    println!(" Number of section headers: {}", elf.e_shnum);
    println!(" Section header string table index: {}", elf.e_shstrndx);
}

fn main() -> io::Result<()> {
    let args = CommandLineArguments::parse();

    if !args.should_load_file() {
        process::exit(1);
    }

    let bytes = fs::read(args.file_path)?;

    if args.file_headers {
        let elf_headers = ELFHeaders::from_bytes(&bytes);

        match elf_headers {
            Ok(elf_headers) => show_headers(elf_headers),
            Err(e) => eprintln!("{:?}", e),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{ELFError, ELFObjectFileType, ELFParser, ELFVersion, ELFABI, ELFISA};

    #[test]
    fn test_get_section_header_table_index_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];
        bytes[4] = 0x02;

        bytes[62] = 0x24;
        bytes[63] = 0x00;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(0x0024);
        let got = elf.get_section_header_table_index();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_number_of_entries_section_header_table_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];
        bytes[4] = 0x02;

        bytes[60] = 0x25;
        bytes[61] = 0x00;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(0x0025);
        let got = elf.get_section_header_entry_count();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_section_header_table_size_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];
        bytes[4] = 0x02;

        bytes[58] = 0x40;
        bytes[59] = 0x00;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(64);
        let got = elf.get_section_header_size();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_number_of_entries_in_program_header_table_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];
        bytes[4] = 0x02;

        bytes[56] = 0x0D;
        bytes[57] = 0x00;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(0x000D);
        let got = elf.get_program_header_entries_number();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_program_header_table_size_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];

        bytes[4] = 0x02;

        bytes[54] = 0x38;
        bytes[55] = 0x00;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(56);
        let got = elf.get_program_header_table_size();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_header_size_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];

        bytes[4] = 0x02;

        bytes[52] = 0x40;
        bytes[53] = 0x00;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(64);
        let got = elf.get_header_size();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_e_flags_64_bits() {
        let mut bytes: [u8; 256] = [0; 256];

        bytes[4] = 0x02;
        bytes[48] = 0;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(0x0);
        let got = elf.get_e_flags();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_program_section_header_start_64bit() {
        let mut bytes: [u8; 256] = [0; 256];

        bytes[4] = 0x02;
        bytes[41] = 0x47;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(18176);
        let got = elf.get_section_header_start();

        println!("{}", elf.is_64bit());

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_program_header_start_64bit() {
        let mut bytes: [u8; 256] = [0; 256];

        bytes[4] = 0x02;
        bytes[32] = 0x40;

        let elf = ELFParser {
            bytes: &bytes.to_vec(),
        };

        let expected = Ok(64);
        let got = elf.get_program_header_start();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_machine_isa_amd64() {
        let elf = ELFParser {
            bytes: &vec![
                0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3E, 0, 0, 0, 0, 0, 0x40,
                0x10, 0, 0, 0, 0, 0, 0,
            ],
        };

        let expected = Ok(ELFISA::AMD64);
        let got = elf.get_machine_instruction_set();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_entry_point() {
        let elf = ELFParser {
            bytes: &vec![
                0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x10,
                0, 0, 0, 0, 0, 0,
            ],
        };

        let expected = Ok(4160);
        let got = elf.get_entry_point();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_e_version_valid() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x4, 0x0, 0xFF,
                0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00,
            ],
        };

        let expected: Result<ELFVersion, ELFError> = Ok(ELFVersion::EVCurrent);
        let got = elf.get_e_version();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_e_version_invalid() {
        let elf = ELFParser { bytes: &vec![0] };

        let expected: Result<ELFVersion, ELFError> = Err(ELFError::InvalidVersion);
        let got = elf.get_e_version();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_core() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x4, 0x0,
            ],
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETCORE);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_dyn() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x3, 0x0,
            ],
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETDYN);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_exec() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x2, 0x0,
            ],
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETEXEC);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_rel() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x0,
            ],
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETREL);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_none() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x0, 0x0,
            ],
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETNONE);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_padding() {
        let elf = ELFParser {
            bytes: &vec![
                0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0,
            ],
        };

        let expected: Result<&[u8], ELFError> = Ok(&[0_u8, 0, 0, 0, 0, 0, 0]);
        let got = elf.get_padding();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_os_abi_hpux() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01],
        };

        let expected = Ok(ELFABI::HpUx);
        let got = elf.get_os_abi();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_os_abi_netbsd() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x02],
        };

        let expected = Ok(ELFABI::NetBsd);
        let got = elf.get_os_abi();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_os_abi_linux() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x03],
        };

        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Linux));
    }

    #[test]
    fn test_os_abi_hurd() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x04],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::GnuHurd));
    }

    #[test]
    fn test_os_abi_solaris() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x06],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Solaris));
    }

    #[test]
    fn test_os_abi_aix() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x07],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Aix));
    }

    #[test]
    fn test_os_abi_irix() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x08],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Irix));
    }

    #[test]
    fn test_os_abi_freebsd() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x09],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::FreeBsd));
    }

    #[test]
    fn test_os_abi_tru64() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0a],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Tru64));
    }

    #[test]
    fn test_os_abi_novellmodesto() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0b],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::NovellModesto));
    }

    #[test]
    fn test_os_abi_openbsd() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0c],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::OpenBsd));
    }

    #[test]
    fn test_os_abi_openvms() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0d],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::OpenVms));
    }

    #[test]
    fn test_os_abi_nonstopkernel() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0e],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::NonstopKernel));
    }

    #[test]
    fn test_os_abi_aros() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0f],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Aros));
    }

    #[test]
    fn test_os_abi_fenixos() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x10],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::FenixOs));
    }

    #[test]
    fn test_os_abi_nuxicloud() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x11],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::NuxiCloudAbi));
    }

    #[test]
    fn test_os_abi_stratustechnologiesopenvos() {
        let elf = ELFParser {
            bytes: &vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x12],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::StratusTechnologiesOpenVos));
    }

    #[test]
    fn test_os_abi_systemv() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x0],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::SystemV));
    }

    #[test]
    fn test_elf_version_current() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1],
        };
        assert_eq!(elf.get_version(), Ok(ELFVersion::EVCurrent));
    }

    #[test]
    fn test_elf_version_none() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 0],
        };
        assert_eq!(elf.get_version(), Ok(ELFVersion::EVNone));
    }

    #[test]
    fn test_little_endian() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 1],
        };

        assert!(!elf.is_big_endian());
        assert!(elf.is_little_endian());
    }

    #[test]
    fn test_big_endian() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2, 2],
        };

        assert!(elf.is_big_endian());
        assert!(!elf.is_little_endian());
    }

    #[test]
    fn identify_64_bit() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 2],
        };

        assert!(elf.is_64bit());
        assert!(!elf.is_32bit());
    }

    #[test]
    fn identify_32_bit() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46, 1],
        };

        assert!(elf.is_32bit());
        assert!(!elf.is_64bit());
    }

    #[test]
    fn identify_elf_file() {
        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x46],
        };
        assert!(elf.is_elf());
    }

    #[test]
    fn identify_not_elf_file() {
        let elf = ELFParser {
            bytes: &vec![0x7C, 0x45, 0x4C, 0x46],
        };
        assert!(!elf.is_elf());

        let elf = ELFParser {
            bytes: &vec![0x7F, 0x4C, 0x4C, 0x46],
        };
        assert!(!elf.is_elf());

        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4F, 0x46],
        };
        assert!(!elf.is_elf());

        let elf = ELFParser {
            bytes: &vec![0x7F, 0x45, 0x4C, 0x4C],
        };
        assert!(!elf.is_elf());
    }
}
