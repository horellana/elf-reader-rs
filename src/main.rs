use std::io;
use std::path::Path;

#[derive(Debug)]
enum ELFError {
    SomeError
}

enum OSABI {
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
    StratusTechnologiesOpenVos = 0x12
}

#[derive(Debug)]
struct ELFHeaders {
}

#[derive(Debug)]
struct ProgramHeader {
}

#[derive(Debug)]
struct SectionHeader {
}

#[derive(Debug)]
struct ELFFile {
    bytes: Vec<u8>
}

impl Default for ELFFile {
    fn default() -> ELFFile {
        ELFFile {bytes: vec!()}
    }
}

impl ELFFile {
    fn is_elf(&self) -> bool {
        self.bytes[0] == 0x7F
            && self.bytes[1] == 0x45
            && self.bytes[2] == 0x4C
            && self.bytes[3] == 0x46
    }

    fn from_file(path: &Path) -> Result<ELFFile, ELFError> {
        let elf_file: ELFFile = ELFFile{
            ..Default::default()
        };

        Ok(elf_file)
    }
}

fn main() -> io::Result<()> {
    let path = Path::new("./foo.txt");
    let elf_result = ELFFile::from_file(path);

    match elf_result {
        Ok(elf) => println!("got elf: {:?}", elf),
        Err(elf_error) => println!("error: {:?}", elf_error)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ELFFile;
    #[test]
    fn identify_elf_file() {
        let elf = ELFFile{bytes: vec![0x7F, 0x45, 0x4C, 0x46]};
        assert!(elf.is_elf());
    }

    #[test]
    fn identify_not_elf_file() {
        let elf = ELFFile{bytes: vec![0x7C, 0x45, 0x4C, 0x46]};
        assert!(! elf.is_elf());

        let elf = ELFFile{bytes: vec![0x7F, 0x4C, 0x4C, 0x46]};
        assert!(! elf.is_elf());

        let elf = ELFFile{bytes: vec![0x7F, 0x45, 0x4F, 0x46]};
        assert!(! elf.is_elf());

        let elf = ELFFile{bytes: vec![0x7F, 0x45, 0x4C, 0x4C]};
        assert!(! elf.is_elf());
    }
}
