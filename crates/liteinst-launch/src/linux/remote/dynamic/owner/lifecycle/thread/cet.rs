//! Read-only shadow-stack qualification for one continuously owned stopped task.
//!
//! The second certificate relies on the documented native Linux ABI: a kernel
//! implementing user shadow stacks exposes both STATUS and the native SHSTK
//! regset. It does not attest a vendor build or infer CONFIG from uname/CPUID.
//! Genuine procfs and uninterposed kernel responses are part of that contract.
use super::*;

const PTRACE_ARCH_PRCTL: libc::c_uint = 30;
const ARCH_GET_FS: usize = 0x1003;
const ARCH_SHSTK_STATUS: usize = 0x5005;
const NT_PRSTATUS: usize = 1;
const NT_X86_SHSTK: usize = 0x204;
const REGISTER_BYTES: usize = 216;
const WORD_BYTES: usize = 8;
const SENTINEL: u64 = u64::MAX;
const MAX_STATUS_BYTES: usize = 16 * 1024;
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DisabledProof {
    ReportedZero,
    NativeInterfacesAbsent,
}

struct WordRead {
    result: Result<(), LaunchError>,
    value: u64,
}

struct RegsetRead<T> {
    result: Result<(), LaunchError>,
    value: T,
    length: usize,
    base_unchanged: bool,
}

/// This is only a private read seam. No implementation can resume, mutate, or
/// replace the actual owner's held stop through this interface.
trait Probe {
    fn status(&mut self) -> WordRead;
    fn registers(&mut self) -> Result<RegisterSnapshot, LaunchError>;
    fn prstatus(&mut self) -> RegsetRead<RegisterSnapshot>;
    fn fsbase(&mut self) -> WordRead;
    fn shadow_stack(&mut self) -> RegsetRead<u64>;
    fn tracer_unfiltered(&mut self) -> Result<(), LaunchError>;
}

fn exact_einval(result: Result<(), LaunchError>) -> Result<(), LaunchError> {
    match result {
        Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::EINVAL) => {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(()) => Err(LaunchError::Invalid(
            "shadow-stack absence requires an absent interface",
        )),
    }
}

fn absent_status(observed: WordRead) -> Result<(), LaunchError> {
    exact_einval(observed.result)?;
    if observed.value != SENTINEL {
        return Err(LaunchError::Invalid(
            "failed shadow-stack status changed its output",
        ));
    }
    Ok(())
}

fn certify(probe: &mut impl Probe) -> Result<DisabledProof, LaunchError> {
    let first = probe.status();
    match first.result {
        Ok(()) if first.value == 0 => return Ok(DisabledProof::ReportedZero),
        Ok(()) => {
            return Err(LaunchError::Invalid(
                "native thread clone requires disabled shadow-stack features",
            ));
        }
        Err(error) => absent_status(WordRead {
            result: Err(error),
            value: first.value,
        })?,
    }

    // A sibling may install a TSYNC seccomp filter during this block. Mode is
    // monotonic, so zero both before and after rules that out. Repeat STATUS
    // inside the bracket; its initial error only selected this proof path.
    probe.tracer_unfiltered()?;
    let before = probe.registers()?;
    if before.cs != 0x33 {
        return Err(LaunchError::Invalid(
            "shadow-stack absence requires native register mode",
        ));
    }
    let general = probe.prstatus();
    general.result?;
    if general.length != REGISTER_BYTES || !general.base_unchanged || general.value != before {
        return Err(LaunchError::Invalid(
            "native register-view authentication failed",
        ));
    }
    let fs = probe.fsbase();
    fs.result?;
    if fs.value != before.fs_base {
        return Err(LaunchError::Invalid(
            "native arch-prctl dispatch authentication failed",
        ));
    }
    absent_status(probe.status())?;
    let shadow = probe.shadow_stack();
    exact_einval(shadow.result)?;
    if shadow.length != WORD_BYTES || !shadow.base_unchanged || shadow.value != SENTINEL {
        return Err(LaunchError::Invalid(
            "failed shadow-stack regset changed its buffer or iovec",
        ));
    }
    if probe.registers()? != before {
        return Err(LaunchError::Invalid(
            "registers changed during shadow-stack qualification",
        ));
    }
    probe.tracer_unfiltered()?;
    Ok(DisabledProof::NativeInterfacesAbsent)
}

struct NativeProbe {
    tid: libc::pid_t,
}

fn query(
    request: libc::c_uint,
    tid: libc::pid_t,
    address: usize,
    data: usize,
    operation: &'static str,
) -> Result<(), LaunchError> {
    // SAFETY: every caller supplies a live tracer-owned output buffer of the
    // request's exact size; the task remains in the owner's authenticated stop.
    let result = unsafe { libc::ptrace(request, tid, address, data) };
    match result {
        0 => Ok(()),
        -1 => Err(system(operation)),
        _ => Err(LaunchError::Invalid(
            "unexpected ptrace qualification return value",
        )),
    }
}

impl NativeProbe {
    fn arch_word(&self, option: usize, operation: &'static str) -> WordRead {
        let mut value = SENTINEL;
        let result = query(
            PTRACE_ARCH_PRCTL,
            self.tid,
            (&raw mut value) as usize,
            option,
            operation,
        );
        WordRead { result, value }
    }
}

impl Probe for NativeProbe {
    fn status(&mut self) -> WordRead {
        self.arch_word(ARCH_SHSTK_STATUS, "ptrace shadow-stack status")
    }

    fn registers(&mut self) -> Result<RegisterSnapshot, LaunchError> {
        // SAFETY: all fields in the native register structure are integers.
        let mut value: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        query(
            libc::PTRACE_GETREGS,
            self.tid,
            0,
            (&raw mut value) as usize,
            "ptrace shadow-stack GETREGS control",
        )?;
        Ok(value.into())
    }

    fn prstatus(&mut self) -> RegsetRead<RegisterSnapshot> {
        // SAFETY: all fields are integers; failure never leaves uninitialized data.
        let mut value: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let base = (&raw mut value).cast::<libc::c_void>();
        let mut iovec = libc::iovec {
            iov_base: base,
            iov_len: std::mem::size_of::<libc::user_regs_struct>(),
        };
        let result = query(
            libc::PTRACE_GETREGSET,
            self.tid,
            NT_PRSTATUS,
            (&raw mut iovec) as usize,
            "ptrace shadow-stack PRSTATUS control",
        );
        RegsetRead {
            result,
            value: value.into(),
            length: iovec.iov_len,
            base_unchanged: iovec.iov_base == base,
        }
    }

    fn fsbase(&mut self) -> WordRead {
        self.arch_word(ARCH_GET_FS, "ptrace shadow-stack GET_FS control")
    }

    fn shadow_stack(&mut self) -> RegsetRead<u64> {
        let mut value = SENTINEL;
        let base = (&raw mut value).cast::<libc::c_void>();
        let mut iovec = libc::iovec {
            iov_base: base,
            iov_len: WORD_BYTES,
        };
        let result = query(
            libc::PTRACE_GETREGSET,
            self.tid,
            NT_X86_SHSTK,
            (&raw mut iovec) as usize,
            "ptrace shadow-stack regset",
        );
        RegsetRead {
            result,
            value,
            length: iovec.iov_len,
            base_unchanged: iovec.iov_base == base,
        }
    }

    fn tracer_unfiltered(&mut self) -> Result<(), LaunchError> {
        tracer_unfiltered()
    }
}

fn status_unfiltered(text: &str, tid: libc::pid_t) -> Result<(), LaunchError> {
    if text.len() > MAX_STATUS_BYTES || !text.ends_with('\n') || text.contains('\0') {
        return Err(LaunchError::Invalid("invalid tracer proc status"));
    }
    let mut pid = None;
    let mut seccomp = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            return Err(LaunchError::Invalid("malformed tracer proc status"));
        };
        match key {
            "Pid" => {
                let value = value.trim();
                if pid.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(LaunchError::Invalid("invalid tracer status identity"));
                }
                pid = value.parse::<libc::pid_t>().ok();
                if pid.is_none() {
                    return Err(LaunchError::Invalid("invalid tracer status identity"));
                }
            }
            "Seccomp" => {
                if seccomp.is_some() || value.trim() != "0" {
                    return Err(LaunchError::Invalid(
                        "shadow-stack absence requires an unfiltered tracer",
                    ));
                }
                seccomp = Some(());
            }
            _ => {}
        }
    }
    if tid <= 0 || pid != Some(tid) || seccomp.is_none() {
        return Err(LaunchError::Invalid(
            "tracer identity or seccomp mode was not authenticated",
        ));
    }
    Ok(())
}

fn tracer_unfiltered() -> Result<(), LaunchError> {
    let file = File::open("/proc/thread-self/status")
        .map_err(|error| io_error("open tracer proc status", error))?;
    // SAFETY: initialized writable statfs storage and one live owned descriptor.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: file remains open throughout the read.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &raw mut filesystem) } != 0 {
        return Err(system("authenticate tracer procfs"));
    }
    if filesystem.f_type != PROC_SUPER_MAGIC {
        return Err(LaunchError::Invalid("tracer status is not on procfs"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read tracer proc status", error))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LaunchError::Invalid("tracer proc status is not UTF-8"))?;
    // SAFETY: gettid has no pointer arguments and identifies this tracer thread.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let tid = libc::pid_t::try_from(tid)
        .map_err(|_| LaunchError::Invalid("invalid tracer thread identifier"))?;
    status_unfiltered(text, tid)
}

pub(super) fn disabled(tid: libc::pid_t) -> Result<DisabledProof, LaunchError> {
    if std::mem::size_of::<libc::user_regs_struct>() != REGISTER_BYTES {
        return Err(LaunchError::Invalid("unsupported native register layout"));
    }
    certify(&mut NativeProbe { tid })
}

mod bounded;
pub(in crate::linux::remote::dynamic::owner) use bounded::{BoundedCet, certify_bounded_cet};

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Outcome {
        Success,
        Errno(i32),
        Refused,
    }

    impl Outcome {
        fn result(self) -> Result<(), LaunchError> {
            match self {
                Self::Success => Ok(()),
                Self::Errno(code) => Err(LaunchError::System {
                    operation: "injected read-only probe",
                    source: io::Error::from_raw_os_error(code),
                }),
                Self::Refused => Err(LaunchError::Invalid("injected read-only refusal")),
            }
        }
    }

    struct Fake {
        status_outcomes: [Outcome; 2],
        status_values: [u64; 2],
        register_outcomes: [Outcome; 2],
        register_values: [RegisterSnapshot; 2],
        prstatus_outcome: Outcome,
        prstatus_value: RegisterSnapshot,
        prstatus_length: usize,
        prstatus_base_unchanged: bool,
        fs_outcome: Outcome,
        fs_value: u64,
        shadow_outcome: Outcome,
        shadow_value: u64,
        shadow_length: usize,
        shadow_base_unchanged: bool,
        seccomp_outcomes: [Outcome; 2],
        status_reads: usize,
        register_reads: usize,
        seccomp_reads: usize,
        calls: Vec<&'static str>,
    }

    impl Fake {
        fn absent() -> Self {
            // SAFETY: the fixture register structure contains only integers.
            let mut registers: RegisterSnapshot =
                unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
            registers.cs = 0x33;
            registers.ss = 0x2b;
            registers.rip = 0x401234;
            registers.rsp = 0x803000;
            registers.fs_base = 0x900000;
            registers.rax = 0x123456789;
            registers.r11 = 0xed7;
            registers.eflags = 0x202;
            Self {
                status_outcomes: [Outcome::Errno(libc::EINVAL); 2],
                status_values: [SENTINEL; 2],
                register_outcomes: [Outcome::Success; 2],
                register_values: [registers; 2],
                prstatus_outcome: Outcome::Success,
                prstatus_value: registers,
                prstatus_length: REGISTER_BYTES,
                prstatus_base_unchanged: true,
                fs_outcome: Outcome::Success,
                fs_value: registers.fs_base,
                shadow_outcome: Outcome::Errno(libc::EINVAL),
                shadow_value: SENTINEL,
                shadow_length: WORD_BYTES,
                shadow_base_unchanged: true,
                seccomp_outcomes: [Outcome::Success; 2],
                status_reads: 0,
                register_reads: 0,
                seccomp_reads: 0,
                calls: Vec::new(),
            }
        }
    }

    impl Probe for Fake {
        fn status(&mut self) -> WordRead {
            self.calls.push("status");
            let index = self.status_reads;
            self.status_reads += 1;
            WordRead {
                result: self.status_outcomes[index].result(),
                value: self.status_values[index],
            }
        }

        fn registers(&mut self) -> Result<RegisterSnapshot, LaunchError> {
            self.calls.push("registers");
            let index = self.register_reads;
            self.register_reads += 1;
            self.register_outcomes[index].result()?;
            Ok(self.register_values[index])
        }

        fn prstatus(&mut self) -> RegsetRead<RegisterSnapshot> {
            self.calls.push("prstatus");
            RegsetRead {
                result: self.prstatus_outcome.result(),
                value: self.prstatus_value,
                length: self.prstatus_length,
                base_unchanged: self.prstatus_base_unchanged,
            }
        }

        fn fsbase(&mut self) -> WordRead {
            self.calls.push("fsbase");
            WordRead {
                result: self.fs_outcome.result(),
                value: self.fs_value,
            }
        }

        fn shadow_stack(&mut self) -> RegsetRead<u64> {
            self.calls.push("shadow_stack");
            RegsetRead {
                result: self.shadow_outcome.result(),
                value: self.shadow_value,
                length: self.shadow_length,
                base_unchanged: self.shadow_base_unchanged,
            }
        }

        fn tracer_unfiltered(&mut self) -> Result<(), LaunchError> {
            self.calls.push("seccomp");
            let index = self.seccomp_reads;
            self.seccomp_reads += 1;
            self.seccomp_outcomes[index].result()
        }
    }

    fn corruptions(original: RegisterSnapshot) -> Vec<RegisterSnapshot> {
        let mut cases = Vec::new();
        macro_rules! each {
            ($($field:ident),+ $(,)?) => {
                $(
                    let mut changed = original;
                    changed.$field ^= 1;
                    cases.push(changed);
                )+
            };
        }
        each!(
            r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip,
            cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs,
        );
        assert_eq!(cases.len(), 27);
        cases
    }

    fn refused(fake: &mut Fake) {
        assert!(certify(fake).is_err());
    }

    #[test]
    fn reported_zero_retains_the_original_positive_status_path() {
        let mut fake = Fake::absent();
        fake.status_outcomes[0] = Outcome::Success;
        fake.status_values[0] = 0;
        // The existing successful STATUS path does not acquire new capability
        // requirements from the separate absence certificate.
        fake.seccomp_outcomes = [Outcome::Refused; 2];
        assert_eq!(certify(&mut fake).unwrap(), DisabledProof::ReportedZero);
        assert_eq!(fake.calls, ["status"]);
    }

    #[test]
    fn exact_absence_requires_both_native_interfaces_inside_the_filter_bracket() {
        let mut fake = Fake::absent();
        assert_eq!(
            certify(&mut fake).unwrap(),
            DisabledProof::NativeInterfacesAbsent
        );
        assert_eq!(
            fake.calls,
            [
                "status",
                "seccomp",
                "registers",
                "prstatus",
                "fsbase",
                "status",
                "shadow_stack",
                "registers",
                "seccomp",
            ]
        );
        assert_eq!(fake.status_reads, 2);
        assert_eq!(fake.register_reads, 2);
        assert_eq!(fake.seccomp_reads, 2);
    }

    #[test]
    fn status_nonzero_other_errors_and_changed_error_outputs_refuse() {
        for value in [1, 2, 3, 1 << 63, SENTINEL] {
            let mut fake = Fake::absent();
            fake.status_outcomes[0] = Outcome::Success;
            fake.status_values[0] = value;
            refused(&mut fake);
            assert_eq!(fake.calls, ["status"]);
        }
        for index in 0..2 {
            for code in [
                libc::ENODEV,
                libc::ENOSYS,
                libc::EIO,
                libc::EFAULT,
                libc::EPERM,
                libc::ESRCH,
                libc::EINTR,
            ] {
                let mut fake = Fake::absent();
                fake.status_outcomes[index] = Outcome::Errno(code);
                let error = certify(&mut fake).unwrap_err();
                assert!(matches!(error, LaunchError::System { source, .. }
                    if source.raw_os_error() == Some(code)));
                assert!(!fake.calls.contains(&"shadow_stack"));
            }
            for value in [0, 1, SENTINEL - 1] {
                let mut fake = Fake::absent();
                fake.status_values[index] = value;
                refused(&mut fake);
                assert!(!fake.calls.contains(&"shadow_stack"));
            }
            let mut fake = Fake::absent();
            fake.status_outcomes[index] = Outcome::Refused;
            refused(&mut fake);
        }
        // A successful second query, including zero, contradicts the absent
        // interface certificate. It cannot silently switch proof paths.
        for value in [0, 1, SENTINEL] {
            let mut fake = Fake::absent();
            fake.status_outcomes[1] = Outcome::Success;
            fake.status_values[1] = value;
            refused(&mut fake);
            assert!(!fake.calls.contains(&"shadow_stack"));
        }
    }

    #[test]
    fn native_register_view_requires_exact_mode_length_buffer_and_all_fields() {
        for mode in [0, 0x23, 0x32, 0x34, SENTINEL] {
            let mut fake = Fake::absent();
            fake.register_values[0].cs = mode;
            fake.prstatus_value.cs = mode;
            refused(&mut fake);
            assert!(!fake.calls.contains(&"prstatus"));
        }
        for length in [0, 8, 68, REGISTER_BYTES - 8, REGISTER_BYTES + 8] {
            let mut fake = Fake::absent();
            fake.prstatus_length = length;
            refused(&mut fake);
            assert!(!fake.calls.contains(&"fsbase"));
        }
        let mut fake = Fake::absent();
        fake.prstatus_base_unchanged = false;
        refused(&mut fake);
        for changed in corruptions(Fake::absent().prstatus_value) {
            let mut fake = Fake::absent();
            fake.prstatus_value = changed;
            refused(&mut fake);
            assert!(!fake.calls.contains(&"fsbase"));
        }
        for outcome in [Outcome::Errno(libc::EINVAL), Outcome::Refused] {
            let mut fake = Fake::absent();
            fake.register_outcomes[0] = outcome;
            refused(&mut fake);
            let mut fake = Fake::absent();
            fake.prstatus_outcome = outcome;
            refused(&mut fake);
        }
    }

    #[test]
    fn reversed_arch_prctl_dispatch_requires_success_and_the_exact_fsbase() {
        for value in [0, 1, 0x900001, SENTINEL] {
            let mut fake = Fake::absent();
            fake.fs_value = value;
            refused(&mut fake);
            assert_eq!(fake.status_reads, 1);
        }
        for outcome in [
            Outcome::Errno(libc::EINVAL),
            Outcome::Errno(libc::EFAULT),
            Outcome::Errno(libc::ESRCH),
            Outcome::Refused,
        ] {
            let mut fake = Fake::absent();
            fake.fs_outcome = outcome;
            refused(&mut fake);
            assert_eq!(fake.status_reads, 1);
        }
    }

    #[test]
    fn shadow_regset_rejects_enodev_success_even_ssp_zero_and_changed_iovecs() {
        for outcome in [
            Outcome::Success,
            Outcome::Errno(libc::ENODEV),
            Outcome::Errno(libc::ENOSYS),
            Outcome::Errno(libc::EIO),
            Outcome::Errno(libc::EFAULT),
            Outcome::Errno(libc::EPERM),
            Outcome::Errno(libc::ESRCH),
            Outcome::Refused,
        ] {
            for value in [0, 0x1000, SENTINEL] {
                let mut fake = Fake::absent();
                fake.shadow_outcome = outcome;
                fake.shadow_value = value;
                refused(&mut fake);
                assert_eq!(fake.seccomp_reads, 1);
            }
        }
        for value in [0, 1, SENTINEL - 1] {
            let mut fake = Fake::absent();
            fake.shadow_value = value;
            refused(&mut fake);
        }
        for length in [0, 4, 7, 9, 16, usize::MAX] {
            let mut fake = Fake::absent();
            fake.shadow_length = length;
            refused(&mut fake);
        }
        let mut fake = Fake::absent();
        fake.shadow_base_unchanged = false;
        refused(&mut fake);
    }

    #[test]
    fn late_filter_or_any_register_change_prevents_absence_certification() {
        for index in 0..2 {
            for outcome in [Outcome::Errno(libc::EIO), Outcome::Refused] {
                let mut fake = Fake::absent();
                fake.seccomp_outcomes[index] = outcome;
                refused(&mut fake);
                assert_eq!(fake.seccomp_reads, index + 1);
            }
        }
        for changed in corruptions(Fake::absent().register_values[0]) {
            let mut fake = Fake::absent();
            fake.register_values[1] = changed;
            refused(&mut fake);
            assert_eq!(fake.seccomp_reads, 1);
        }
        let mut fake = Fake::absent();
        fake.register_outcomes[1] = Outcome::Errno(libc::ESRCH);
        refused(&mut fake);
    }

    #[test]
    fn tracer_status_requires_unique_zero_mode_and_the_current_thread_identity() {
        assert!(status_unfiltered("Name:\ttracer\nPid:\t42\nSeccomp:\t0\n", 42).is_ok());
        assert!(status_unfiltered("Pid: 42\nSeccomp: 0\nSeccomp_filters: 0\n", 42).is_ok());
        for text in [
            "Pid: 42\n",
            "Seccomp: 0\n",
            "Pid: 41\nSeccomp: 0\n",
            "Pid: 42\nPid: 42\nSeccomp: 0\n",
            "Pid: 42\nSeccomp: 0\nSeccomp: 0\n",
            "Pid: 42\nSeccomp: 0\nSeccomp: 2\n",
            "Pid: 42\nSeccomp: 1\n",
            "Pid: 42\nSeccomp: 2\n",
            "Pid: 42\nSeccomp: 3\n",
            "Pid: 42\nSeccomp: -1\n",
            "Pid: 42\nSeccomp: +0\n",
            "Pid: 42\nSeccomp: 00\n",
            "Pid: 42\nSeccomp: 0 garbage\n",
            "Pid: 42\nSeccomp: \n",
            "Pid: +42\nSeccomp: 0\n",
            "Pid: 4294967296\nSeccomp: 0\n",
            "Pid: 42 42\nSeccomp: 0\n",
            "Pid: 42\nSeccomp: 0",
            "Pid: 42\nSeccomp: 0\n\0",
            "Pid: 42\nnot a field\nSeccomp: 0\n",
        ] {
            assert!(status_unfiltered(text, 42).is_err(), "accepted {text:?}");
        }
        assert!(status_unfiltered("Pid: 0\nSeccomp: 0\n", 0).is_err());
        assert!(status_unfiltered("Pid: 42\nSeccomp: 0\n", -1).is_err());
        let oversized = format!(
            "Name: {}\nPid: 42\nSeccomp: 0\n",
            "x".repeat(MAX_STATUS_BYTES)
        );
        assert!(status_unfiltered(&oversized, 42).is_err());
    }
}
