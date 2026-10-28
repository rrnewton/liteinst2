//! Test-only, same-owner local resource observations. No control authority.
//! All recording storage exists before the attempt. Drop hooks never allocate,
//! parse, assert, or unwind; unexpected recorder misuse fails the command.
use super::super::super::source_identity::backing::query::{Query, REQUEST};
use super::*;
use std::cell::{RefCell, RefMut};
use std::rc::Rc;

const SLOTS: usize = 6;
const MAP_BYTES: usize = 65536;
const PAGE_BYTES: usize = 4096;
pub(in crate::linux::remote::dynamic::owner) const ABORT_MAGIC: u64 = 0x4241434b41425254;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Outcome {
    result: i64,
    errno: Option<i32>,
}
impl Outcome {
    fn capture(result: i64) -> Self {
        Self {
            result,
            errno: if result < 0 {
                std::io::Error::last_os_error().raw_os_error()
            } else {
                None
            },
        }
    }
    fn zero() -> Self {
        Self {
            result: 0,
            errno: None,
        }
    }
    fn error(errno: i32) -> Self {
        Self {
            result: -1,
            errno: Some(errno),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner) enum ProbeFd {
    Directory,
    Executable,
    Maps,
}
impl ProbeFd {
    fn index(self) -> usize {
        match self {
            Self::Directory => 0,
            Self::Executable => 1,
            Self::Maps => 2,
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct Closed {
    fd: i32,
    result: Outcome,
    next_getfd: Outcome,
    explicit: bool,
    order: u32,
}
#[derive(Clone, Copy, Debug)]
struct NativeFile {
    stat: Outcome,
    getfd: Outcome,
    identity: [u64; 5],
}
fn native_file(fd: i32) -> NativeFile {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = Outcome::capture(i64::from(unsafe { libc::fstat(fd, &mut stat) }));
    let getfd = Outcome::capture(i64::from(unsafe { libc::fcntl(fd, libc::F_GETFD) }));
    NativeFile {
        stat: result,
        getfd,
        identity: [
            u64::from(libc::major(stat.st_dev)),
            u64::from(libc::minor(stat.st_dev)),
            stat.st_ino,
            u64::from(stat.st_mode),
            stat.st_size as u64,
        ],
    }
}
#[derive(Clone, Copy, Debug)]
struct QueryCall {
    request: (i32, libc::c_ulong, u64),
    result: Outcome,
    before: Query,
    after: Query,
    name_len: usize,
    name_address: u64,
}
// Explicit UAPI fields, including every output and the unchanged input pointers.
fn query_words(q: Query) -> [u64; 13] {
    [
        q.size,
        q.query_flags,
        q.query_addr,
        q.vma_start,
        q.vma_end,
        q.vma_flags,
        q.vma_page_size,
        q.vma_offset,
        q.inode,
        u64::from(q.dev_major) | (u64::from(q.dev_minor) << 32),
        u64::from(q.vma_name_size) | (u64::from(q.build_id_size) << 32),
        q.vma_name_addr,
        q.build_id_addr,
    ]
}
#[derive(Clone, Copy, Debug, Default)]
struct Record {
    until: Option<Instant>,
    wrong_unmap: bool,
    fd: Option<i32>,
    address: u64,
    mapped: u32,
    initial_file: Option<NativeFile>,
    maps_open: Option<Outcome>,
    maps_fs: Option<Outcome>,
    filesystem: i64,
    maps_read: Option<Outcome>,
    maps_close: Option<Outcome>,
    maps_len: usize,
    maps_rows: usize,
    production_query: Option<QueryCall>,
    production_reads: u32,
    production_last: Option<Outcome>,
    production_first_arguments: Option<(i32, u64, usize)>,
    production_last_arguments: Option<(i32, u64, usize)>,
    null_read: bool,
    production_identity: Option<([u64; 5], [u64; 3])>,
    unmap: Option<Outcome>,
    submitted: u64,
    unmap_explicit: bool,
    unmapped: u32,
    mincore: Option<Outcome>,
    final_file: Option<NativeFile>,
    closes: [Option<Closed>; 3],
    checked_mapped: bool,
}
struct Storage {
    count: usize,
    clock: u32,
    rows: [Record; SLOTS],
    maps: Vec<u8>,
    query_names: Vec<u8>,
    abort_receipt: Option<i32>,
}
pub(in crate::linux::remote::dynamic::owner) struct ExecBackingInspection {
    storage: RefCell<Storage>,
}
#[derive(Clone)]
pub(in crate::linux::remote::dynamic::owner) struct Probe {
    inspection: Rc<ExecBackingInspection>,
    index: usize,
}
fn fatal() -> ! {
    std::process::abort()
}
fn tick(storage: &mut Storage) -> u32 {
    storage.clock = match storage.clock.checked_add(1) {
        Some(value) => value,
        None => fatal(),
    };
    storage.clock
}
fn saved_error(error: &Option<LaunchError>) -> Option<i32> {
    match error {
        Some(LaunchError::System { source, .. }) => source.raw_os_error(),
        None => None,
        _ => fatal(),
    }
}
impl ExecBackingInspection {
    pub(in crate::linux::remote::dynamic::owner) fn new(abort_receipt: Option<i32>) -> Self {
        Self {
            storage: RefCell::new(Storage {
                count: 0,
                clock: 0,
                rows: [Record::default(); SLOTS],
                maps: vec![0; SLOTS * MAP_BYTES],
                query_names: vec![0; SLOTS * MAP_BYTES],
                abort_receipt,
            }),
        }
    }
    fn storage(&self) -> RefMut<'_, Storage> {
        self.storage.try_borrow_mut().unwrap_or_else(|_| fatal())
    }
    fn mapped_value(&self, index: usize) -> ([u64; 5], [u64; 3]) {
        // Only called by assertions outside Drop/native recording intervals.
        let storage = self.storage.borrow();
        assert!(index < storage.count);
        let row = storage.rows[index];
        assert!(row.mapped > 0);
        assert_eq!(row.address % PAGE_BYTES as u64, 0);
        assert_ne!(row.address, 0);
        assert!(row.maps_open.unwrap().result >= 0);
        assert_eq!(row.maps_open.unwrap().errno, None);
        assert_eq!(row.maps_fs, Some(Outcome::zero()));
        assert_eq!(row.filesystem, libc::PROC_SUPER_MAGIC);
        assert_eq!(row.maps_read, Some(Outcome::zero()));
        assert_eq!(row.maps_close, Some(Outcome::zero()));
        assert!(row.maps_len > 0 && row.maps_len < MAP_BYTES);
        let bytes = &storage.maps[index * MAP_BYTES..][..row.maps_len];
        let maps = crate::exec_oracle_support::Maps::parse_self(bytes.to_vec(), row.maps_rows);
        let end = row.address.checked_add(PAGE_BYTES as u64).unwrap();
        let overlaps = maps
            .rows
            .iter()
            .filter(|entry| entry.start < end && row.address < entry.end)
            .collect::<Vec<_>>();
        assert_eq!(overlaps.len(), 1);
        let map = overlaps[0];
        assert_eq!((map.start, map.end, map.offset), (row.address, end, 0));
        assert_eq!(map.permissions, "---p");
        assert!(map.inode > 0 && map.path.as_ref().is_some_and(|path| !path.is_empty()));
        let (major, minor) = map.device.split_once(':').unwrap();
        let vma = [
            u64::from_str_radix(major, 16).unwrap(),
            u64::from_str_radix(minor, 16).unwrap(),
            map.inode,
        ];
        let file = row.initial_file.unwrap();
        assert_eq!(file.stat, Outcome::zero());
        assert_eq!(
            file.getfd,
            Outcome {
                result: i64::from(libc::FD_CLOEXEC),
                errno: None
            }
        );
        assert_eq!(
            file.identity[3] & u64::from(libc::S_IFMT),
            u64::from(libc::S_IFREG)
        );
        assert!(file.identity[2] > 0 && file.identity[4] > 0);
        (file.identity, vma)
    }
    pub(in crate::linux::remote::dynamic::owner) fn check_mapped(&self, index: usize) {
        self.mapped_value(index);
        self.storage().rows[index].checked_mapped = true;
    }
    pub(in crate::linux::remote::dynamic::owner) fn check(
        &self,
        count: usize,
        until: Instant,
        fault: Option<ExecFault>,
    ) {
        assert_eq!(self.storage.borrow().count, count);
        for index in 0..count {
            let observed = self.mapped_value(index);
            let row = self.storage.borrow().rows[index];
            assert_eq!(row.until, Some(until));
            assert!(!row.wrong_unmap);
            assert_eq!(row.submitted, row.address);
            assert_eq!(row.unmap, Some(Outcome::zero()));
            assert_eq!(row.mincore, Some(Outcome::error(libc::ENOMEM)));
            assert_eq!(row.final_file.unwrap().stat, Outcome::zero());
            assert_eq!(
                row.final_file.unwrap().identity,
                row.initial_file.unwrap().identity
            );
            assert_eq!(
                row.final_file.unwrap().getfd,
                row.initial_file.unwrap().getfd
            );
            assert!(row.mapped < row.unmapped);
            let complete = matches!(fault, None | Some(ExecFault::MapsQueryUnsupported));
            assert_eq!(row.unmap_explicit, complete);
            let directory = row.closes[0].unwrap();
            let executable = row.closes[1].unwrap();
            assert!(directory.order < row.mapped);
            assert!(row.unmapped < executable.order);
            assert_eq!(Some(executable.fd), row.fd);
            assert!(directory.explicit);
            assert_eq!(executable.explicit, complete);
            for closed in row.closes.iter().flatten() {
                assert!(closed.fd >= 0);
                assert_eq!(closed.result, Outcome::zero());
                assert_eq!(closed.next_getfd, Outcome::error(libc::EBADF));
            }
            match fault {
                None | Some(ExecFault::MapsQueryUnsupported) => {
                    assert_eq!(row.production_identity, Some(observed));
                    let q = row
                        .production_query
                        .expect("one actual query before success");
                    let forced_legacy =
                        fault == Some(ExecFault::MapsQueryUnsupported) && index == 0;
                    self.check_query(index, forced_legacy, observed.1);
                    if q.result == Outcome::zero() {
                        assert!(!forced_legacy);
                        Self::no_reads(row);
                    } else {
                        assert_eq!(q.result, Outcome::error(libc::ENOTTY));
                        assert!(row.production_reads > 0);
                        assert_eq!(row.production_last, Some(Outcome::zero()));
                        let first = row.production_first_arguments.unwrap();
                        let last = row.production_last_arguments.unwrap();
                        assert_eq!((first.0, first.2), (row.closes[2].unwrap().fd, MAP_BYTES));
                        assert_eq!(last.0, first.0);
                        assert!(first.1 != 0 && last.1 != 0 && last.2 > 0 && last.2 <= MAP_BYTES);
                        assert!(!row.null_read);
                    }
                    let maps = row.closes[2].unwrap();
                    assert!(maps.explicit && row.mapped < maps.order && maps.order < row.unmapped);
                }
                Some(ExecFault::MapsRead) => {
                    assert!(row.production_query.is_none());
                    assert!(row.production_identity.is_none());
                    assert_eq!(row.production_reads, 1);
                    assert_eq!(row.production_last, Some(Outcome::error(libc::EFAULT)));
                    assert!(row.null_read);
                    let arguments = (row.closes[2].unwrap().fd, 0, MAP_BYTES);
                    assert_eq!(row.production_first_arguments, Some(arguments));
                    assert_eq!(row.production_last_arguments, Some(arguments));
                    let maps = row.closes[2].unwrap();
                    assert!(maps.explicit && row.mapped < maps.order && maps.order < row.unmapped);
                }
                Some(ExecFault::MapsQuery) => {
                    assert!(row.production_identity.is_none());
                    let q = row.production_query.expect("actual null query");
                    assert_eq!(q.request, (row.closes[2].unwrap().fd, REQUEST, 0));
                    assert_eq!(q.result, Outcome::error(libc::EFAULT));
                    Self::query_input(q.before, row.address, q.name_address);
                    assert_eq!(query_words(q.after), query_words(q.before));
                    assert_eq!(q.name_len, 0);
                    Self::no_reads(row);
                    let maps = row.closes[2].unwrap();
                    assert!(maps.explicit && row.mapped < maps.order && maps.order < row.unmapped);
                }
                Some(ExecFault::AfterMapPanic) => {
                    assert!(row.production_query.is_none());
                    assert!(row.production_identity.is_none() && row.production_last.is_none());
                    assert_eq!(row.production_reads, 0);
                    assert!(
                        row.production_first_arguments.is_none()
                            && row.production_last_arguments.is_none()
                    );
                    assert!(!row.null_read && row.closes[2].is_none());
                }
                _ => panic!("unexpected backing inspection fault"),
            }
        }
        assert!(Instant::now() < until);
    }
    fn no_reads(row: Record) {
        assert_eq!(row.production_reads, 0);
        assert!(row.production_last.is_none());
        assert!(
            row.production_first_arguments.is_none() && row.production_last_arguments.is_none()
        );
        assert!(!row.null_read);
    }
    fn query_input(q: Query, address: u64, name_address: u64) {
        assert_eq!(REQUEST, 0xc068_6611);
        assert_eq!(q.size, 104);
        assert_eq!((q.query_flags, q.query_addr), (0, address));
        assert_eq!(
            (
                q.vma_start,
                q.vma_end,
                q.vma_flags,
                q.vma_page_size,
                q.vma_offset,
                q.inode
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            (q.dev_major, q.dev_minor, q.build_id_size, q.build_id_addr),
            (0, 0, 0, 0)
        );
        assert_eq!(q.vma_name_size as usize, MAP_BYTES);
        assert_ne!(q.vma_name_addr, 0);
        assert_eq!(q.vma_name_addr, name_address);
    }
    fn check_query(&self, index: usize, forced_legacy: bool, identity: [u64; 3]) {
        let storage = self.storage.borrow();
        let row = storage.rows[index];
        let q = row.production_query.unwrap();
        assert_eq!(
            (q.request.0, q.request.1),
            (
                row.closes[2].unwrap().fd,
                if forced_legacy { 0 } else { REQUEST }
            )
        );
        assert_ne!(q.request.2, 0);
        Self::query_input(q.before, row.address, q.name_address);
        if q.result != Outcome::zero() {
            assert_eq!(q.result, Outcome::error(libc::ENOTTY));
            assert_eq!(query_words(q.after), query_words(q.before));
            assert_eq!(q.name_len, 0);
            return;
        }
        assert!(!forced_legacy);
        let a = q.after;
        assert_eq!(
            (
                a.size,
                a.query_flags,
                a.query_addr,
                a.vma_name_addr,
                a.build_id_size,
                a.build_id_addr
            ),
            (104, 0, row.address, q.before.vma_name_addr, 0, 0)
        );
        assert_eq!(
            (
                a.vma_start,
                a.vma_end,
                a.vma_flags,
                a.vma_page_size,
                a.vma_offset
            ),
            (
                row.address,
                row.address.checked_add(PAGE_BYTES as u64).unwrap(),
                0,
                PAGE_BYTES as u64,
                0
            )
        );
        assert_eq!(
            [u64::from(a.dev_major), u64::from(a.dev_minor), a.inode],
            identity
        );
        assert_eq!(q.name_len, a.vma_name_size as usize);
        assert!((2..=MAP_BYTES).contains(&q.name_len));
        let name = &storage.query_names[index * MAP_BYTES..][..q.name_len];
        assert_eq!(name.last(), Some(&0));
        assert!(!name[..name.len() - 1].contains(&0));
        let bytes = &storage.maps[index * MAP_BYTES..][..row.maps_len];
        let maps = crate::exec_oracle_support::Maps::parse_self(bytes.to_vec(), row.maps_rows);
        let map = maps
            .rows
            .iter()
            .find(|entry| entry.start == row.address)
            .unwrap();
        assert_eq!(
            &name[..name.len() - 1],
            map.path.as_ref().unwrap().as_bytes()
        );
    }
}
impl Probe {
    pub(in crate::linux::remote::dynamic::owner) fn begin(
        owner: &Owner,
        until: Instant,
    ) -> Result<Option<Self>, GateError> {
        let Some(inspection) = &owner.exec_backing else {
            return Ok(None);
        };
        owner.time_left(until, "private exec backing observation")?;
        let mut storage = inspection.storage();
        if storage.count == SLOTS {
            return Err(GateError::Refused("private exec backing observation full"));
        }
        let index = storage.count;
        storage.count += 1;
        storage.rows[index].until = Some(until);
        storage.rows[index].wrong_unmap = owner.take_exec_fault(ExecFault::MunmapUnaligned);
        drop(storage);
        Ok(Some(Self {
            inspection: Rc::clone(inspection),
            index,
        }))
    }
    pub(in crate::linux::remote::dynamic::owner) fn current(owner: &Owner) -> Option<Self> {
        owner.exec_backing.as_ref().map(|inspection| {
            let count = inspection.storage().count;
            if count == 0 {
                fatal();
            }
            Self {
                inspection: Rc::clone(inspection),
                index: count - 1,
            }
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn mapped(&self, fd: i32, address: u64) {
        let mut storage = self.inspection.storage();
        if storage.rows[self.index].mapped != 0 {
            fatal();
        }
        let order = tick(&mut storage);
        let mut row = storage.rows[self.index];
        row.fd = Some(fd);
        row.address = address;
        row.mapped = order;
        row.initial_file = Some(native_file(fd));
        let maps = unsafe {
            libc::open(
                c"/proc/self/maps".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        row.maps_open = Some(Outcome::capture(i64::from(maps)));
        if maps >= 0 {
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            row.maps_fs = Some(Outcome::capture(i64::from(unsafe {
                libc::fstatfs(maps, &mut fs)
            })));
            row.filesystem = fs.f_type;
            loop {
                let mut extra = 0_u8;
                let remaining = MAP_BYTES - row.maps_len;
                let pointer = if remaining == 0 {
                    &raw mut extra
                } else {
                    storage.maps[self.index * MAP_BYTES + row.maps_len..].as_mut_ptr()
                };
                let read =
                    Outcome::capture(
                        unsafe { libc::read(maps, pointer.cast(), remaining.max(1)) } as i64,
                    );
                row.maps_read = Some(read);
                if read.result <= 0 || remaining == 0 {
                    break;
                }
                let amount = read.result as usize;
                if amount > remaining {
                    fatal();
                }
                row.maps_len += amount;
                if row.until.is_none_or(|until| Instant::now() >= until) {
                    break;
                }
            }
            row.maps_close = Some(Outcome::capture(i64::from(unsafe { libc::close(maps) })));
            if row.maps_close.is_none_or(|result| result.result != 0) {
                fatal();
            }
        }
        row.maps_rows = storage.maps[self.index * MAP_BYTES..][..row.maps_len]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        storage.rows[self.index] = row;
    }
    pub(in crate::linux::remote::dynamic::owner) fn maps_query(
        &self,
        request: (i32, libc::c_ulong, u64),
        result: i32,
        error: &Option<LaunchError>,
        before: &Query,
        after: &Query,
        name: &[u8],
    ) {
        let mut storage = self.inspection.storage();
        let length = if result == 0 {
            after.vma_name_size as usize
        } else {
            0
        };
        if name.len() != MAP_BYTES || length > MAP_BYTES {
            fatal();
        }
        storage.query_names[self.index * MAP_BYTES..][..length].copy_from_slice(&name[..length]);
        if storage.rows[self.index]
            .production_query
            .replace(QueryCall {
                request,
                result: Outcome {
                    result: i64::from(result),
                    errno: saved_error(error),
                },
                before: *before,
                after: *after,
                name_len: length,
                name_address: name.as_ptr() as usize as u64,
            })
            .is_some()
        {
            fatal();
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn maps_read(
        &self,
        result: isize,
        error: &Option<LaunchError>,
        request: (i32, u64, usize),
    ) {
        let mut storage = self.inspection.storage();
        let row = &mut storage.rows[self.index];
        row.production_reads = match row.production_reads.checked_add(1) {
            Some(value) => value,
            None => fatal(),
        };
        row.production_last = Some(Outcome {
            result: result as i64,
            errno: saved_error(error),
        });
        row.production_first_arguments.get_or_insert(request);
        row.production_last_arguments = Some(request);
        row.null_read |= request.1 == 0;
    }
    pub(in crate::linux::remote::dynamic::owner) fn identity(
        &self,
        opened: [u64; 5],
        vma: [u64; 3],
    ) {
        let mut storage = self.inspection.storage();
        if storage.rows[self.index]
            .production_identity
            .replace((opened, vma))
            .is_some()
        {
            fatal();
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn unmap_address(
        &self,
        address: *mut libc::c_void,
    ) -> *mut libc::c_void {
        let storage = self.inspection.storage();
        if storage.rows[self.index].wrong_unmap {
            address.wrapping_byte_add(1)
        } else {
            address
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn unmapped(
        &self,
        fd: i32,
        address: u64,
        submitted: u64,
        result: i32,
        errno: Option<i32>,
        explicit: bool,
    ) {
        // No open/allocation occurs in this interval. mincore covers the entire
        // exact single-page owned interval, not an equality lookup of a VMA.
        let mut resident = 0_u8;
        let absent = Outcome::capture(i64::from(unsafe {
            libc::mincore(
                address as usize as *mut libc::c_void,
                PAGE_BYTES,
                &raw mut resident,
            )
        }));
        let file = native_file(fd);
        let mut storage = self.inspection.storage();
        let order = tick(&mut storage);
        let row = &mut storage.rows[self.index];
        if row.unmap.is_some() {
            fatal();
        }
        row.submitted = submitted;
        row.unmap = Some(Outcome {
            result: i64::from(result),
            errno,
        });
        row.unmap_explicit = explicit;
        row.unmapped = order;
        row.mincore = Some(absent);
        row.final_file = Some(file);
        let same_file = row.initial_file.is_some_and(|before| {
            file.stat == Outcome::zero()
                && file.identity == before.identity
                && file.getfd == before.getfd
        });
        let flags = u64::from(row.checked_mapped)
            | (u64::from(absent == Outcome::zero()) << 1)
            | (u64::from(same_file) << 2);
        let receipt = storage.abort_receipt;
        drop(storage);
        if let Some(receipt) = receipt.filter(|_| result != 0) {
            // This is an actual post-syscall failure receipt. No assertion
            // can divert the real release failure into an unrelated abort.
            let words = [
                ABORT_MAGIC,
                3,
                address,
                submitted,
                PAGE_BYTES as u64,
                result as i64 as u64,
                errno.unwrap_or(0) as u64,
                flags,
            ];
            if unsafe {
                libc::write(
                    receipt,
                    words.as_ptr().cast(),
                    std::mem::size_of_val(&words),
                )
            } != 64
            {
                fatal();
            }
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn closed(
        &self,
        role: ProbeFd,
        fd: i32,
        result: i32,
        error: &Option<LaunchError>,
        explicit: bool,
    ) {
        // This is this tracer's NEXT descriptor operation after close. The
        // actual close result proves release; this strict instantaneous query
        // adds evidence and is never treated as retained incarnation authority.
        let next = Outcome::capture(i64::from(unsafe { libc::fcntl(fd, libc::F_GETFD) }));
        let observed = Outcome {
            result: i64::from(result),
            errno: saved_error(error),
        };
        let mut storage = self.inspection.storage();
        let order = tick(&mut storage);
        if storage.rows[self.index].closes[role.index()]
            .replace(Closed {
                fd,
                result: observed,
                next_getfd: next,
                explicit,
                order,
            })
            .is_some()
        {
            fatal();
        }
    }
}
