use std::fs;
use std::io;
use std::path::Path;

extern crate endianness;
use endianness::*;

#[derive(Debug)]
#[derive(PartialEq)]
enum ELFISA {
    NoSpecificInstructionSet = 0x00,
    ATTWE32100 = 0x01,
    SPARC = 0x02,
    X86 = 0x03,
    AMD64 = 0x3E
}

#[derive(Debug)]
#[derive(PartialEq)]
enum ELFVersion {
    EVNone = 0,
    EVCurrent = 1,
}

#[derive(Debug)]
#[derive(PartialEq)]
enum ELFError {
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

#[derive(PartialEq)]
#[derive(Debug)]
enum ELFPadding {
}

#[derive(PartialEq)]
#[derive(Debug)]
enum ELFABIVersion {
    Unspecified
}

#[derive(PartialEq)]
#[derive(Debug)]
enum ELFObjectFileType {
    ETNONE = 0x00,
    ETREL = 0x01,
    ETEXEC = 0x02,
    ETDYN = 0x03,
    ETCORE = 0x04,
    ETLOOS = 0xFE00,
    ETHIOS = 0xFEFF,
    ETLOPROC = 0xFF00,
    ETHIPROC = 0xFFFF
}

#[derive(PartialEq)]
#[derive(Debug)]
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

#[derive(Debug)]
#[derive(PartialEq)]
struct ELFFile {
    bytes: Vec<u8>,
}

impl Default for ELFFile {
    fn default() -> ELFFile {
        ELFFile { bytes: vec![] }
    }
}

impl ELFFile {
    fn get_section_header_start(&self) -> Result<u16, ELFError> {
        let size = if self.is_64bit() { 8 } else { 4 };
        let start = 39;

        let mut bytes: [u8; 8] = [ 0, 0, 0, 0, 0, 0, 0, 0 ];
        let mut bytes_position = 0;

        for i in start..start+size {
            if self.bytes[i] != 0 {
                bytes[bytes_position] = self.bytes[i];
                bytes_position = bytes_position + 1;
            }
        }

        let endianess = if self.is_big_endian() { ByteOrder::BigEndian } else { ByteOrder::LittleEndian };
        let section_start = read_u16(&bytes, endianess);

        match section_start {
            Ok(section_start) => Ok(section_start),
            _ => Err(ELFError::InvalidSectionHeaderStart)
        }
    }

    fn get_program_header_start(&self) -> Result<u16, ELFError> {
        let size = if self.is_64bit() { 8 } else { 4 };
        let start = 31;

        let mut bytes: [u8; 8] = [ 0, 0, 0, 0, 0, 0, 0, 0 ];
        let mut bytes_position = 0;

        for i in start..start+size {
            if self.bytes[i] != 0 {
                bytes[bytes_position] = self.bytes[i];
                bytes_position = bytes_position + 1;
            }
        }

        println!("{:?}", bytes);

        let endianess = if self.is_big_endian() { ByteOrder::BigEndian } else { ByteOrder::LittleEndian };
        let header_start = read_u16(&bytes, endianess);

        match header_start {
            Ok(header_start) => Ok(header_start),
            _ => Err(ELFError::InvalidProgramHeaderStart)
        }
    }

    fn get_machine_string(&self) -> &'static str {
        match self.get_machine_instruction_set() {
            Ok(ELFISA::AMD64) => "Advanced Micro Devices X86-64",
            _ => "Unknown ISA"
        }
    }

    fn get_machine_instruction_set(&self) -> Result<ELFISA, ELFError> {
        match (self.bytes[18], self.bytes[19]) {
            (0x3E, 0x00) => Ok(ELFISA::AMD64),
            _ => Err(ELFError::InvalidIsa)
        }
    }

    fn get_entry_point(&self) -> Result<u16, ELFError> {
        let start = 23;
        let size = if self.is_64bit() { 8 } else { 4 };
        let mut bytes: [u8; 8] = [ 0, 0, 0, 0, 0, 0, 0, 0 ];
        let mut bytes_position = 0;

        for i in start..start+size {
            if self.bytes[i] != 0 {
                bytes[bytes_position] = self.bytes[i];
                bytes_position = bytes_position + 1;
            }
        }

        let endianness = if self.is_big_endian() {
            ByteOrder::BigEndian
        }
        else {
            ByteOrder::LittleEndian
        };

        let entry = read_u16(&bytes, endianness);

        match entry {
            Ok(entry) => Ok(entry),
            _ => Err(ELFError::InvalidEntryPoint)
        }
    }

    fn get_endianness_string(&self) -> &'static str {
        if self.is_big_endian() {
            "big endian"
        }
        else {
            "little endian"
        }
    }

    fn get_e_version(&self) -> Result<ELFVersion, ELFError> {
        match self.bytes[22] {
            0x01 => Ok(ELFVersion::EVCurrent),
            _ => Err(ELFError::InvalidVersion)
        }
    }

    fn get_object_file_type_string(&self) -> &'static str {
        match self.get_object_file_type() {
            Ok(ELFObjectFileType::ETNONE) => "None",
            Ok(ELFObjectFileType::ETDYN) => "DYN (Position-Independent Executable file)",
            _ => "Unknown"
        }
    }

    fn get_object_file_type(&self) -> Result<ELFObjectFileType, ELFError> {
        match (self.bytes[16], self.bytes[17]) {
            (0x00, 0x00) => Ok(ELFObjectFileType::ETNONE),
            (0x01, 0x00) => Ok(ELFObjectFileType::ETREL),
            (0x02, 0x00) => Ok(ELFObjectFileType::ETEXEC),
            (0x03, 0x00) => Ok(ELFObjectFileType::ETDYN),
            (0x04, 0x00) => Ok(ELFObjectFileType::ETCORE),
            _ => Err(ELFError::InvalidObjectFileType)
        }
    }

    fn get_padding(&self) -> Result<&[u8], ELFError> {
        if self.bytes.len() >= 16 {
            Ok(&(self.bytes)[9..16])
        }
        else {
            Err(ELFError::InvalidPadding)
        }
    }

    fn get_abi_version_string(&self) -> &'static str {
        match self.get_abi_version() {
            Ok(ELFABIVersion::Unspecified) => "0",
            _ => "Unknown ABI Version"
        }
    }

    fn get_abi_version(&self) -> Result<ELFABIVersion, ELFError> {
        match self.bytes[8] {
            0 => Ok(ELFABIVersion::Unspecified),
            _ => Err(ELFError::InvalidAbiVersion)
        }
    }

    fn get_os_abi_string(&self) -> &'static str {
        match self.get_os_abi() {
            Ok(ELFABI::SystemV) => "Unix - System V",
            _ => "Unknown"
        }
    }

    fn get_os_abi(&self) -> Result<ELFABI, ELFError> {
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

    fn get_version(&self) -> Result<ELFVersion, ELFError> {
        match self.bytes[6] {
            0 => Ok(ELFVersion::EVNone),
            1 => Ok(ELFVersion::EVCurrent),
            _ => Err(ELFError::InvalidVersion),
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

    fn from_file(path: &Path) -> Result<ELFFile, ELFError> {
        let bytes_result = fs::read(path);

        match bytes_result {
            Ok(bytes) => Ok(ELFFile { bytes: bytes }),
            _ => Err(ELFError::InvalidFile)
        }
    }
}

fn show_headers(elf: ELFFile) -> Result<(), ELFError>{
    let program_header_start = elf.get_program_header_start()?;

    println!("ELF Header:");
    println!(" Magic: ");
    println!(" Class: {}", if elf.is_64bit() { "ELF64" } else { "ELF32" });
    println!(" Data: {}", elf.get_endianness_string());
    println!(" Version: {}", if elf.get_version() == Ok(ELFVersion::EVCurrent) { "1 (Current)" } else { "0" });
    println!(" OS/ABI: {}", elf.get_os_abi_string());
    println!(" ABI Version: {}", if elf.get_abi_version() == Err(ELFError::InvalidAbiVersion) { "1" } else { "0" });
    println!(" Type: {}", elf.get_object_file_type_string());
    println!(" Machine: {}", elf.get_machine_string());
    println!(" Entry point address: {:#01X}", elf.get_entry_point().unwrap_or_default());
    println!(" Start of program headers: {} (bytes into file)", program_header_start);

    Ok(())
}

fn main() -> io::Result<()> {
    let path = Path::new("./test/example.elf");
    let elf_result = ELFFile::from_file(path);

    match elf_result {
        Ok(elf) => {
            elf.get_program_header_start();
            show_headers(elf);
        },
        _ => {
            println!("Could not load elf file");
        }
    }

    return Ok(());
}

#[cfg(test)]
mod tests {
    use crate::{ELFFile, ELFVersion, ELFISA, ELFABI, ELFObjectFileType, ELFError};

    // #[test]
    // fn test_get_program_section_header_start_64bit() {
    //     let elf = ELFFile {
    //         bytes: vec![0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0 ,0, 0x40, 0x10, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0x47, 0, 0, 0, 0 ,0 ,0]
    //     };

    //     let expected = Some(56);
    //     let got = elf.get_section_header_start();

    //     assert_eq!(expected, got);
    // }

    #[test]
    fn test_get_program_header_start_64bit() {
        let elf = ELFFile {
            bytes: vec![0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0 ,0, 0x40, 0x10, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0]
        };

        let expected = Ok(64);
        let got = elf.get_program_header_start();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_machine_isa_amd64() {
        let elf = ELFFile {
            bytes: vec![0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3E, 0, 0 ,0 ,0 ,0, 0x40, 0x10, 0, 0, 0, 0, 0, 0]
        };

        let expected = Ok(ELFISA::AMD64);
        let got = elf.get_machine_instruction_set();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_entry_point() {
        let elf = ELFFile {
            bytes: vec![0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0 ,0, 0x40, 0x10, 0, 0, 0, 0, 0, 0]
        };

        let expected = Ok(4160);
        let got = elf.get_entry_point();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_e_version_valid() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x4, 0x0, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00]
        };

        let expected: Result<ELFVersion, ELFError> = Ok(ELFVersion::EVCurrent);
        let got = elf.get_e_version();

        assert_eq!(expected, got);
    }


    #[test]
    fn test_get_e_version_invalid() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x4, 0x0, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        };

        let expected: Result<ELFVersion, ELFError> = Err(ELFError::InvalidVersion);
        let got = elf.get_e_version();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_core() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x4, 0x0]
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETCORE);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_dyn() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x3, 0x0]
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETDYN);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_exec() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x2, 0x0]
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETEXEC);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_rel() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x0]
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETREL);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_object_file_type_none() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0, 0x0, 0x0]
        };

        let expected: Result<ELFObjectFileType, ELFError> = Ok(ELFObjectFileType::ETNONE);
        let got = elf.get_object_file_type();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_get_padding() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01, 1, 0, 0, 0, 0, 0, 0, 0],
        };

        let expected: Result<&[u8], ELFError> = Ok(&[0 as u8, 0, 0, 0, 0, 0, 0]);
        let got = elf.get_padding();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_os_abi_hpux() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x01],
        };

        let expected = Ok(ELFABI::HpUx);
        let got = elf.get_os_abi();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_os_abi_netbsd() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x02],
        };

        let expected = Ok(ELFABI::NetBsd);
        let got = elf.get_os_abi();

        assert_eq!(expected, got);
    }

    #[test]
    fn test_os_abi_linux() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x03],
        };

        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Linux));
    }

    #[test]
    fn test_os_abi_hurd() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x04],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::GnuHurd));
    }

    #[test]
    fn test_os_abi_solaris() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x06],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Solaris));
    }

    #[test]
    fn test_os_abi_aix() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x07],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Aix));
    }

    #[test]
    fn test_os_abi_irix() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x08],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Irix));
    }

    #[test]
    fn test_os_abi_freebsd() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x09],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::FreeBsd));
    }

    #[test]
    fn test_os_abi_tru64() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0a],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Tru64));
    }

    #[test]
    fn test_os_abi_novellmodesto() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0b],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::NovellModesto));
    }

    #[test]
    fn test_os_abi_openbsd() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0c],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::OpenBsd));
    }

    #[test]
    fn test_os_abi_openvms() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0d],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::OpenVms));
    }

    #[test]
    fn test_os_abi_nonstopkernel() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0e],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::NonstopKernel));
    }

    #[test]
    fn test_os_abi_aros() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x0f],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::Aros));
    }

    #[test]
    fn test_os_abi_fenixos() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x10],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::FenixOs));
    }

    #[test]
    fn test_os_abi_nuxicloud() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x11],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::NuxiCloudAbi));
    }

    #[test]
    fn test_os_abi_stratustechnologiesopenvos() {
        let elf = ELFFile {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0x12],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::StratusTechnologiesOpenVos));
    }

    #[test]
    fn test_os_abi_systemv() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0x0],
        };
        assert_eq!(elf.get_os_abi(), Ok(ELFABI::SystemV));
    }

    #[test]
    fn test_elf_version_current() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 1],
        };
        assert_eq!(elf.get_version(), Ok(ELFVersion::EVCurrent));
    }

    #[test]
    fn test_elf_version_none() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1, 0],
        };
        assert_eq!(elf.get_version(), Ok(ELFVersion::EVNone));
    }

    #[test]
    fn test_little_endian() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 1],
        };

        assert!(!elf.is_big_endian());
        assert!(elf.is_little_endian());
    }

    #[test]
    fn test_big_endian() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2, 2],
        };

        assert!(elf.is_big_endian());
        assert!(!elf.is_little_endian());
    }

    #[test]
    fn identify_64_bit() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 2],
        };

        assert!(elf.is_64bit());
        assert!(!elf.is_32bit());
    }

    #[test]
    fn identify_32_bit() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46, 1],
        };

        assert!(elf.is_32bit());
        assert!(!elf.is_64bit());
    }

    #[test]
    fn identify_elf_file() {
        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x46],
        };
        assert!(elf.is_elf());
    }

    #[test]
    fn identify_not_elf_file() {
        let elf = ELFFile {
            bytes: vec![0x7C, 0x45, 0x4C, 0x46],
        };
        assert!(!elf.is_elf());

        let elf = ELFFile {
            bytes: vec![0x7F, 0x4C, 0x4C, 0x46],
        };
        assert!(!elf.is_elf());

        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4F, 0x46],
        };
        assert!(!elf.is_elf());

        let elf = ELFFile {
            bytes: vec![0x7F, 0x45, 0x4C, 0x4C],
        };
        assert!(!elf.is_elf());
    }
}
