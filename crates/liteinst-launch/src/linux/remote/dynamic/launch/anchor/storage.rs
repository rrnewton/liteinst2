use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct KernelAction {
    pub(super) handler: u64,
    pub(super) flags: u64,
    pub(super) restorer: u64,
    pub(super) mask: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct KernelStack {
    pub(super) address: u64,
    // Native ss_flags occupies the low word; the initialized padding is zero.
    pub(super) flags: u64,
    pub(super) size: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct Packet {
    pub(super) magic: u64,
    pub(super) session: u64,
    pub(super) kind: u64,
    pub(super) sequence: u64,
    pub(super) tid: u64,
    pub(super) mask: u64,
    pub(super) reserved: [u64; 2],
}
const _: () = assert!(std::mem::size_of::<Packet>() == 64);

/// All fields are initialized integer data. The child writes only its private
/// copy, never the tracer's mapping or shared backing storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C, align(16))]
pub(super) struct Context {
    pub(super) session: u64,
    pub(super) stack_low: u64,
    pub(super) stack_top: u64,
    pub(super) channel: u64,
    pub(super) parent_channel: u64,
    pub(super) release: u64,
    pub(super) parent_release: u64,
    pub(super) error_read: u64,
    pub(super) error_write: u64,
    pub(super) program: u64,
    pub(super) argv: u64,
    pub(super) envp: u64,
    pub(super) uid: u64,
    pub(super) tid: u64,
    pub(super) old_mask: u64,
    pub(super) probe_mask: u64,
    pub(super) current_mask: u64,
    pub(super) pending: u64,
    pub(super) old_action: KernelAction,
    pub(super) probe_action: KernelAction,
    pub(super) check_action: KernelAction,
    pub(super) old_stack: KernelStack,
    pub(super) check_stack: KernelStack,
    pub(super) signal: [u64; 16],
    pub(super) frame: u64,
    pub(super) ucontext: u64,
    pub(super) siginfo: u64,
    pub(super) metadata: [u64; 3],
    pub(super) prepared: Packet,
    pub(super) anchor: Packet,
    pub(super) release_byte: u64,
    pub(super) error: [i32; 2],
    pub(super) reserved: [u64; 4],
}
const _: () = assert!(std::mem::size_of::<Context>() <= 4096);

pub(super) struct Storage {
    mapping: *mut libc::c_void,
    length: usize,
    pub(super) context: *mut Context,
    // The pre-clone lifetime is confined to the original dedicated tracer.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Storage {
    pub(super) fn new(
        session: u64,
        bootstrap: Bootstrap,
        channel: i32,
        parent_channel: i32,
    ) -> Result<Self, LaunchError> {
        if page_size()? != 4096 || session == 0 || channel < 0 || parent_channel < 0 {
            return Err(LaunchError::Invalid(
                "unsupported initial anchor storage profile",
            ));
        }
        // context, guard, bounded stack, guard: every possible frame byte must
        // lie inside the single private stack region authenticated below.
        let length = 4096 * 3 + STACK_BYTES;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(system("map initial anchor storage"));
        }
        let this = Self {
            mapping,
            length,
            context: mapping.cast(),
            _thread: std::marker::PhantomData,
        };
        let stack = unsafe { mapping.cast::<u8>().add(8192) };
        if unsafe { libc::mprotect(mapping, 4096, libc::PROT_READ | libc::PROT_WRITE) } != 0
            || unsafe {
                libc::mprotect(
                    stack.cast(),
                    STACK_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
        {
            return Err(system("protect initial anchor storage"));
        }
        let mut context: Context = unsafe { std::mem::zeroed() };
        context.session = session;
        context.stack_low = stack as u64;
        context.stack_top = (stack as u64) + STACK_BYTES as u64;
        context.channel = channel as u64;
        context.parent_channel = parent_channel as u64;
        context.release = bootstrap.release as u64;
        context.parent_release = bootstrap.parent_release as u64;
        context.error_read = bootstrap.error_read as u64;
        context.error_write = bootstrap.error_write as u64;
        context.program = bootstrap.program as u64;
        context.argv = bootstrap.argv as u64;
        context.envp = bootstrap.envp as u64;
        context.uid = unsafe { libc::getuid() } as u64;
        context.probe_mask = BLOCKED & !(1_u64 << (PROBE_SIGNAL - 1));
        context.probe_action = KernelAction {
            handler: raw::handler_address(),
            flags: 0x0400_0004,
            restorer: raw::restorer_address(),
            mask: BLOCKED,
        };
        let signal = unsafe {
            std::slice::from_raw_parts_mut(context.signal.as_mut_ptr().cast::<u8>(), 128)
        };
        signal[0..4].copy_from_slice(&PROBE_SIGNAL.to_ne_bytes());
        signal[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
        signal[20..24].copy_from_slice(&(context.uid as u32).to_ne_bytes());
        signal[24..32].copy_from_slice(&session.to_ne_bytes());
        context.prepared = Packet {
            magic: MAGIC,
            session,
            kind: 1,
            sequence: 1,
            tid: 0,
            mask: BLOCKED,
            reserved: [0; 2],
        };
        context.anchor = Packet {
            kind: 2,
            sequence: 2,
            ..context.prepared
        };
        unsafe { std::ptr::write(this.context, context) };
        Ok(this)
    }
    pub(super) fn configuration(&self, channel: i32, parent_channel: i32) -> ChildConfig {
        ChildConfig {
            context: self.context,
            channel,
            parent_channel,
        }
    }
    pub(super) fn initial(&self) -> Context {
        unsafe { *self.context }
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping, self.length);
        }
    }
}

pub(super) fn read_context(tid: i32, address: u64) -> Result<Context, LaunchError> {
    let mut context: Context = unsafe { std::mem::zeroed() };
    let output = unsafe {
        std::slice::from_raw_parts_mut(
            (&raw mut context).cast::<u8>(),
            std::mem::size_of::<Context>(),
        )
    };
    read_into(tid, address, output)?;
    Ok(context)
}

/// Read only into preallocated initialized storage. No allocation after effect.
pub(super) fn read_into(tid: i32, address: u64, output: &mut [u8]) -> Result<(), LaunchError> {
    read_prefix(tid, address, output, &mut 0)
}

pub(super) fn read_prefix(
    tid: i32,
    address: u64,
    output: &mut [u8],
    copied: &mut usize,
) -> Result<(), LaunchError> {
    *copied = 0;
    let end = address
        .checked_add(output.len() as u64)
        .ok_or(LaunchError::Invalid("anchor read overflow"))?;
    let mut cursor = address;
    while cursor < end {
        let base = cursor & !7;
        let value = unsafe {
            *libc::__errno_location() = 0;
            let word = libc::ptrace(libc::PTRACE_PEEKDATA, tid, base as usize, 0);
            if word == -1 && *libc::__errno_location() != 0 {
                return Err(system("read owned anchor bytes"));
            }
            (word as u64).to_ne_bytes()
        };
        let offset = (cursor - base) as usize;
        let count = (8 - offset).min((end - cursor) as usize);
        let target = (cursor - address) as usize;
        output[target..target + count].copy_from_slice(&value[offset..offset + count]);
        cursor += count as u64;
        *copied += count;
    }
    Ok(())
}
