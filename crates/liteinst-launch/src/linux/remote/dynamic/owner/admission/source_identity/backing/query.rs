//! Linux 6.11 PROCMAP_QUERY: one self-consistent VMA observation, not an
//! inventory of the tracer's concurrently changing address space.
use super::*;

// Linux UAPI <linux/fs.h>, struct procmap_query and
// _IOWR('f', 17, struct procmap_query), on this x86-64-only backend.
pub(in crate::linux::remote::dynamic::owner) const REQUEST: libc::c_ulong = 0xc068_6611;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::linux::remote::dynamic::owner) struct Query {
    pub size: u64,
    pub query_flags: u64,
    pub query_addr: u64,
    pub vma_start: u64,
    pub vma_end: u64,
    pub vma_flags: u64,
    pub vma_page_size: u64,
    pub vma_offset: u64,
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub vma_name_size: u32,
    pub build_id_size: u32,
    pub vma_name_addr: u64,
    pub build_id_addr: u64,
}
const _: () = assert!(size_of::<Query>() == 104);

impl Query {
    pub(super) fn new(address: u64, storage: &mut [u8]) -> Self {
        Self {
            size: size_of::<Self>() as u64,
            query_addr: address,
            vma_name_size: storage.len() as u32,
            vma_name_addr: storage.as_mut_ptr() as usize as u64,
            ..Self::default()
        }
    }
    pub(super) fn identity(&self, address: u64, storage: &[u8]) -> Result<FileIdentity, GateError> {
        let end = address
            .checked_add(PAGE)
            .filter(|_| address != 0 && address % PAGE == 0)
            .ok_or_else(|| refused("exec identity probe geometry differs"))?;
        if self.size != size_of::<Self>() as u64
            || self.query_flags != 0
            || self.query_addr != address
            || self.vma_name_addr != storage.as_ptr() as usize as u64
            || self.build_id_addr != 0
            || self.build_id_size != 0
        {
            return Err(refused("exec identity query request changed"));
        }
        if self.vma_start != address || self.vma_end != end {
            return Err(refused("exec identity probe mapping is absent or merged"));
        }
        let length = self.vma_name_size as usize;
        if self.vma_flags != 0
            || self.vma_offset != 0
            || self.inode == 0
            || self.vma_page_size != PAGE
            || !(2..=storage.len()).contains(&length)
            || storage[length - 1] != 0
            || storage[..length - 1].contains(&0)
        {
            return Err(refused("exec identity probe mapping differs"));
        }
        Ok(FileIdentity {
            major: self.dev_major,
            minor: self.dev_minor,
            inode: self.inode,
        })
    }
}

#[cfg(test)]
mod tests;
