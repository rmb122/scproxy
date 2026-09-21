//! Layouts of recvfrom/recvmsg buffers in the supported native 64-bit ABIs.
use super::{access, memory};
use std::io;

pub(super) struct Message {
    pub name: u64,
    pub name_length: u32,
    pub control: u64,
    pub control_length: usize,
    pub vectors: Vec<(u64, usize)>,
    pub header: Option<u64>,
    pub length_pointer: Option<u64>,
}
impl Message {
    pub fn flat(
        tid: u32,
        buffer: u64,
        length: u64,
        name: u64,
        length_pointer: u64,
        receive: bool,
    ) -> io::Result<Self> {
        let name_length = if name == 0 {
            0
        } else if receive {
            memory::u32_at(tid, length_pointer)?
        } else {
            length_pointer as u32
        };
        Ok(Self {
            name,
            name_length,
            control: 0,
            control_length: 0,
            vectors: vec![(buffer, length as usize)],
            header: None,
            length_pointer: (receive && name != 0).then_some(length_pointer),
        })
    }
    pub fn header(tid: u32, pointer: u64) -> io::Result<Self> {
        let bytes = memory::read(tid, pointer, 56)?;
        let word = |offset| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let count = word(24) as usize;
        if count > 1024 {
            return Err(memory::error(libc::EMSGSIZE));
        }
        let vectors = memory::read(tid, word(16), count * 16)?
            .as_chunks::<16>()
            .0
            .iter()
            .map(|vector| {
                (
                    u64::from_ne_bytes(vector[..8].try_into().unwrap()),
                    u64::from_ne_bytes(vector[8..].try_into().unwrap()) as usize,
                )
            })
            .collect();
        Ok(Self {
            name: word(0),
            name_length: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
            control: word(32),
            control_length: word(40) as usize,
            vectors,
            header: Some(pointer),
            length_pointer: None,
        })
    }
    pub fn capacity(&self) -> io::Result<usize> {
        self.vectors.iter().try_fold(0usize, |size, &(_, length)| {
            size.checked_add(length)
                .filter(|&value| value <= isize::MAX as usize)
                .ok_or_else(|| memory::error(libc::EINVAL))
        })
    }
    pub fn read_payload(&self, tid: u32) -> io::Result<Vec<u8>> {
        let size = self.capacity()?;
        if size > 65507 {
            return Err(memory::error(libc::EMSGSIZE));
        }
        let mut data = vec![0; size];
        let mut offset = 0;
        for &(address, length) in &self.vectors {
            access::read_exact(tid, address, &mut data[offset..offset + length])?;
            offset += length;
        }
        Ok(data)
    }
    pub fn write_payload(&self, tid: u32, bytes: &[u8]) -> io::Result<()> {
        let mut remaining = bytes;
        for &(pointer, length) in &self.vectors {
            let count = length.min(remaining.len());
            access::write_exact(tid, pointer, &remaining[..count])?;
            remaining = &remaining[count..];
            if remaining.is_empty() {
                break;
            }
        }
        Ok(())
    }
    pub fn finish(
        &self,
        tid: u32,
        source: std::net::SocketAddrV4,
        control: &[u8],
        flags: i32,
    ) -> io::Result<()> {
        if self.name != 0 {
            memory::put_address(tid, self.name, self.name_length, source)?;
        }
        if let Some(pointer) = self.length_pointer {
            access::write_exact(tid, pointer, &16u32.to_ne_bytes())?;
        }
        if let Some(header) = self.header {
            access::write_exact(
                tid,
                header + 8,
                &(if self.name == 0 { 0u32 } else { 16 }).to_ne_bytes(),
            )?;
            access::write_exact(tid, self.control, control)?;
            access::write_exact(tid, header + 40, &(control.len() as u64).to_ne_bytes())?;
            access::write_exact(tid, header + 48, &flags.to_ne_bytes())?;
        }
        Ok(())
    }
}
