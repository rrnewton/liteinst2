//! Closed development input and bounded output. Digests identify retained
//! bytes; they do not replace the full artifact or confer execution authority.
use super::{
    OracleError,
    artifact::{ArtifactPlan, PlannedKind},
};
use sha2::{Digest as _, Sha256};
use std::{ffi::OsString, fmt, mem::size_of, os::unix::ffi::OsStrExt, path::Path};

const ARG_BYTES: usize = 4095;
pub(super) const ROW_BYTES: usize = 64 * 1024;
const PLAN_DOMAIN: &[u8] = b"liteinst-runtime-stack-consumer-plan\0v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Digest(pub(super) [u8; 32]);

impl Digest {
    pub(super) fn parse(value: &[u8]) -> Result<Self, OracleError> {
        if value.len() != 64 {
            return Err(OracleError::Invalid("oracle digest length differs"));
        }
        let mut result = [0_u8; 32];
        for (index, pair) in value.chunks_exact(2).enumerate() {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(OracleError::Invalid("oracle digest is not lowercase hex")),
            };
            result[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
        }
        Ok(Self(result))
    }

    pub(super) fn file(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Canonical little-endian scalars, explicit domains and lengths. No
    /// decoded-Instruction Rust layout, address normalization or Debug text.
    pub(super) fn plan(plan: &ArtifactPlan, file: Self) -> Result<Self, OracleError> {
        let mut hash = Sha256::new();
        hash.update(PLAN_DOMAIN);
        hash.update(file.0);
        for value in [
            plan.entry,
            plan.start.start,
            plan.start.end,
            plan.helper.start,
            plan.helper.end,
            plan.read_load.start,
            plan.read_load.end,
            plan.text_load.start,
            plan.text_load.end,
            u64::try_from(plan.read_filesz)
                .map_err(|_| OracleError::Invalid("plan read size overflows"))?,
            u64::try_from(plan.text_filesz)
                .map_err(|_| OracleError::Invalid("plan text size overflows"))?,
            u64::try_from(plan.len()).map_err(|_| OracleError::Invalid("plan count overflows"))?,
            u64::try_from(plan.call)
                .map_err(|_| OracleError::Invalid("plan CALL index overflows"))?,
            u64::try_from(plan.ret)
                .map_err(|_| OracleError::Invalid("plan RET index overflows"))?,
        ] {
            hash.update(value.to_le_bytes());
        }
        for ordinal in plan.syscalls {
            hash.update(
                u64::try_from(ordinal)
                    .map_err(|_| OracleError::Invalid("plan syscall index overflows"))?
                    .to_le_bytes(),
            );
        }
        for instruction in plan.instructions() {
            hash.update(
                u64::try_from(instruction.ordinal())
                    .map_err(|_| OracleError::Invalid("plan ordinal overflows"))?
                    .to_le_bytes(),
            );
            hash.update(instruction.pc().to_le_bytes());
            hash.update(instruction.next_pc().to_le_bytes());
            let (tag, number): (u8, u64) = match instruction.kind() {
                PlannedKind::Ordinary => (0, 0),
                PlannedKind::Call => (1, 0),
                PlannedKind::Ret => (2, 0),
                PlannedKind::Syscall { number } => (3, number),
            };
            hash.update([tag]);
            hash.update(number.to_le_bytes());
            hash.update(
                u64::try_from(instruction.bytes().len())
                    .map_err(|_| OracleError::Invalid("plan encoding size overflows"))?
                    .to_le_bytes(),
            );
            hash.update(instruction.bytes());
        }
        Ok(Self(hash.finalize().into()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Protocol,
    Inspect,
    Run,
}

/// Arguments are installed before checking their contents. No cloned PathBuf,
/// collected Vec or reconstructed command string is needed by the child.
pub(super) struct Input {
    arguments: [Option<OsString>; 8],
    count: usize,
    started: bool,
    mode: Option<Mode>,
    file: Option<Digest>,
    plan: Option<Digest>,
}

impl Input {
    pub(super) fn empty() -> Self {
        Self {
            arguments: std::array::from_fn(|_| None),
            count: 0,
            started: false,
            mode: None,
            file: None,
            plan: None,
        }
    }

    pub(super) fn capture(
        &mut self,
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<(), OracleError> {
        if self.started {
            return Err(OracleError::Invalid("oracle arguments reused"));
        }
        self.started = true;
        let mut arguments = arguments.into_iter();
        for slot in &mut self.arguments {
            let Some(value) = arguments.next() else { break };
            *slot = Some(value);
            self.count += 1;
            if slot.as_ref().unwrap().len() > ARG_BYTES {
                return Err(OracleError::Invalid("oracle argument exceeds bound"));
            }
        }
        // Seven includes argv[0]. The eighth slot preserves the observed
        // surplus argument; an unconsumed later suffix cannot make it valid.
        if self.count > 7 {
            return Err(OracleError::Invalid("oracle has surplus arguments"));
        }
        let mode = match self.count {
            2 if self.argument(1)? == b"--protocol-version" => Mode::Protocol,
            5 if self.argument(1)? == b"--inspect-artifact" => Mode::Inspect,
            7 if self.argument(1)? == b"--artifact" => Mode::Run,
            _ => return Err(OracleError::Invalid("oracle command shape differs")),
        };
        if mode != Mode::Protocol {
            require_path(self.argument(2)?)?;
            if self.argument(3)? != b"--expect-sha256" {
                return Err(OracleError::Invalid("oracle artifact digest flag differs"));
            }
            self.file = Some(Digest::parse(self.argument(4)?)?);
            if mode == Mode::Run {
                if self.argument(5)? != b"--expect-plan-sha256" {
                    return Err(OracleError::Invalid("oracle plan digest flag differs"));
                }
                self.plan = Some(Digest::parse(self.argument(6)?)?);
            }
        }
        self.mode = Some(mode);
        Ok(())
    }

    fn argument(&self, index: usize) -> Result<&[u8], OracleError> {
        self.arguments
            .get(index)
            .and_then(Option::as_ref)
            .map(|value| value.as_os_str().as_bytes())
            .ok_or(OracleError::Invalid("oracle argument is absent"))
    }

    pub(super) fn mode(&self) -> Result<Mode, OracleError> {
        self.mode
            .ok_or(OracleError::Invalid("oracle command is incomplete"))
    }

    pub(super) fn path(&self) -> Result<&Path, OracleError> {
        if !matches!(self.mode, Some(Mode::Inspect | Mode::Run)) {
            return Err(OracleError::Invalid("oracle command has no artifact"));
        }
        Ok(Path::new(
            self.arguments[2]
                .as_ref()
                .ok_or(OracleError::Invalid("oracle path is absent"))?,
        ))
    }

    pub(super) fn expected_file(&self) -> Option<Digest> {
        self.file
    }
    pub(super) fn expected_plan(&self) -> Option<Digest> {
        self.plan
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize, OracleError> {
        self.arguments
            .iter()
            .flatten()
            .try_fold(size_of::<Self>(), |total, arg| {
                total
                    .checked_add(arg.capacity())
                    .ok_or(OracleError::Invalid("oracle argument capacity overflows"))
            })
    }
}

fn require_path(path: &[u8]) -> Result<(), OracleError> {
    if !path.starts_with(b"target/evaluation/admission/")
        || path.contains(&0)
        || path
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(OracleError::Invalid(
            "oracle artifact path is not normalized below evaluation",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WriteOutcome {
    pub(super) requested: usize,
    pub(super) returned: isize,
    pub(super) errno: i32,
}

/// The complete record exists before the one stdout write. Overflow is sticky;
/// neither a truncated row nor a repeated publication can become success.
pub(super) struct Row {
    bytes: [u8; ROW_BYTES],
    length: usize,
    overflowed: bool,
    published: Option<WriteOutcome>,
}

impl Row {
    pub(super) const fn empty() -> Self {
        Self {
            bytes: [0; ROW_BYTES],
            length: 0,
            overflowed: false,
            published: None,
        }
    }

    pub(super) fn initialized(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub(super) fn published(&self) -> Option<WriteOutcome> {
        self.published
    }

    pub(super) fn publish(&mut self) -> Result<(), OracleError> {
        if self.overflowed
            || self.published.is_some()
            || self.length == 0
            || self.initialized().last() != Some(&b'\n')
        {
            return Err(OracleError::Invalid(
                "oracle output is incomplete, overflowed or repeated",
            ));
        }
        // SAFETY: the fixed initialized prefix stays live for this bounded
        // write. Partial/EINTR writes remain failures without a retry.
        let returned = unsafe {
            *libc::__errno_location() = 0;
            libc::write(libc::STDOUT_FILENO, self.bytes.as_ptr().cast(), self.length)
        };
        let errno = unsafe { *libc::__errno_location() };
        self.published = Some(WriteOutcome {
            requested: self.length,
            returned,
            errno,
        });
        if returned != self.length as isize || errno != 0 {
            return Err(OracleError::Io {
                operation: "write oracle result",
                errno: (errno != 0).then_some(errno),
            });
        }
        Ok(())
    }
}

impl fmt::Write for Row {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.overflowed || self.published.is_some() {
            return Err(fmt::Error);
        }
        let Some(end) = self
            .length
            .checked_add(text.len())
            .filter(|end| *end <= ROW_BYTES)
        else {
            self.overflowed = true;
            return Err(fmt::Error);
        };
        self.bytes[self.length..end].copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
}

// Pinned sha2 0.10.9 / digest 0.10.7 / block-buffer 0.10.4 /
// cpufeatures 0.2.17 source-value allowance. Sum both x86 backends, including
// sequential helper copies; this is not a measured ABI or compiler-frame bound.
// evaluation/admission/runtime-stack-consumer-sha-accounting.md records the
// payload derivation and control-header census.
fn sha256_dependency_temporary_bytes() -> Result<usize, OracleError> {
    type InputWords =
        std::iter::Zip<std::slice::IterMut<'static, u32>, std::slice::ChunksExact<'static, u8>>;
    type OutputWords =
        std::iter::Zip<std::slice::ChunksExactMut<'static, u8>, std::slice::Iter<'static, u32>>;
    [
        // Software schedule, rounds, state and block conversion arrays.
        883 * size_of::<[u32; 4]>() + 1556 * size_of::<u32>(),
        // SHA-NI body, round expansions and schedule argument/result copies.
        178 * size_of::<std::arch::x86_64::__m128i>(),
        // By-value wrapper chain, both outputs and the extra padding block.
        4 * size_of::<Sha256>() + 2 * size_of::<[u8; 32]>() + size_of::<[u8; 64]>(),
        // CPUID records, argument/result copies and bit-test operands.
        4 * size_of::<std::arch::x86_64::CpuidResult>() + 20 * size_of::<u32>(),
        // Thin borrows/raw pointers, fat slices and captured-reference closures.
        64 * size_of::<*const u8>() + 48 * size_of::<&[u8]>() + 6 * size_of::<&mut [u32; 8]>(),
        // Lengths, indices, range values, length encoding and branch/tag values.
        96 * size_of::<usize>()
            + 24 * size_of::<std::ops::Range<usize>>()
            + size_of::<[u64; 8]>()
            + 48 * size_of::<bool>()
            + 12 * size_of::<u8>(),
        // SHA-NI scalar intrinsic arguments; vector values are charged above.
        100 * size_of::<i32>() + 2 * size_of::<i64>(),
        // Outer block loops, padding iterator and explicit per-item return slots.
        4 * size_of::<std::slice::Iter<'static, [u8; 64]>>()
            + 4 * size_of::<Option<&[u8; 64]>>()
            + 2 * size_of::<std::slice::IterMut<'static, u8>>()
            + 2 * size_of::<Option<&mut u8>>(),
        // Conversion and output loops: component iterators, Zip and Option item.
        2 * size_of::<InputWords>()
            + 2 * size_of::<OutputWords>()
            + 2 * size_of::<std::slice::IterMut<'static, u32>>()
            + 2 * size_of::<std::slice::ChunksExact<'static, u8>>()
            + 2 * size_of::<std::slice::ChunksExactMut<'static, u8>>()
            + 2 * size_of::<std::slice::Iter<'static, u32>>()
            + 2 * size_of::<Option<(&mut u32, &[u8])>>()
            + 2 * size_of::<Option<(&mut [u8], &u32)>>(),
        // Initialization/conversion Results and copied fixed byte arguments.
        2 * size_of::<Result<sha2::Sha256VarCore, sha2::digest::InvalidOutputSize>>()
            + 2 * size_of::<Result<[u8; 4], std::array::TryFromSliceError>>()
            + 4 * size_of::<[u8; 4]>()
            + 2 * size_of::<[u8; 8]>()
            + 2 * size_of::<[u8; 32]>(),
        // Dispatch cache/order/token-return metadata (not tracee CPU evidence).
        size_of::<std::sync::atomic::AtomicU8>()
            + 4 * size_of::<std::sync::atomic::Ordering>()
            + 2 * size_of::<((), bool)>(),
        // This size calculator's own fixed array/iterator/result/control values.
        size_of::<[usize; 12]>()
            + size_of::<std::array::IntoIter<usize, 12>>()
            + 2 * size_of::<Result<usize, OracleError>>()
            + size_of::<Option<usize>>()
            + 6 * size_of::<usize>(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        total.checked_add(term).ok_or(OracleError::Invalid(
            "oracle SHA dependency temporary size overflows",
        ))
    })
}

pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
    [
        size_of::<Sha256>(),
        2 * size_of::<Digest>(),
        17 * size_of::<u64>(),
        size_of::<std::env::ArgsOs>(),
        8 * size_of::<OsString>(),
        size_of::<fmt::Arguments<'static>>(),
        size_of::<WriteOutcome>(),
        sha256_dependency_temporary_bytes()?,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        total.checked_add(term).ok_or(OracleError::Invalid(
            "oracle protocol temporary size overflows",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn parse(args: &[&str]) -> Result<Input, OracleError> {
        let mut input = Input::empty();
        input.capture(args.iter().map(OsString::from))?;
        Ok(input)
    }

    #[test]
    fn consumer_protocol_accepts_only_three_closed_commands() {
        assert_eq!(
            parse(&["oracle", "--protocol-version"])
                .unwrap()
                .mode()
                .unwrap(),
            Mode::Protocol
        );
        let inspect = [
            "oracle",
            "--inspect-artifact",
            "target/evaluation/admission/run/program",
            "--expect-sha256",
            HASH,
        ];
        assert_eq!(parse(&inspect).unwrap().mode().unwrap(), Mode::Inspect);
        assert_eq!(
            parse(&[
                "oracle",
                "--artifact",
                inspect[2],
                "--expect-sha256",
                HASH,
                "--expect-plan-sha256",
                HASH
            ])
            .unwrap()
            .mode()
            .unwrap(),
            Mode::Run
        );
        for invalid in [
            vec!["oracle"],
            vec!["oracle", "--protocol-version", "extra"],
            vec!["oracle", "--artifact", inspect[2], "--expect-sha256", HASH],
            vec![
                "oracle",
                "--inspect-artifact",
                inspect[2],
                "--expect-sha256",
                HASH,
                "--expect-plan-sha256",
                HASH,
            ],
            vec![
                "oracle",
                "--artifact",
                inspect[2],
                "--expect-sha256",
                HASH,
                "--expect-sha256",
                HASH,
            ],
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn consumer_protocol_refuses_noncanonical_paths_and_digest_text() {
        for path in [
            b"/tmp/program".as_slice(),
            b"target/evaluation/admission/../program",
            b"target/evaluation/admission//program",
            b"target/evaluation/admission/./program",
            b"target/evaluation/admission/",
            b"target/evaluation/admission/a\0b",
        ] {
            assert!(require_path(path).is_err());
        }
        assert!(Digest::parse(&[b'0'; 63]).is_err());
        assert!(Digest::parse(&[b'0'; 65]).is_err());
        assert!(Digest::parse(&[b'A'; 64]).is_err());
        assert!(Digest::parse(&[b'g'; 64]).is_err());
        assert_eq!(Digest::parse(&[b'f'; 64]).unwrap().0, [255; 32]);
    }

    #[test]
    fn consumer_protocol_retains_failed_argument_prefix_and_refuses_reuse() {
        let mut input = Input::empty();
        let huge = "x".repeat(ARG_BYTES + 1);
        assert!(
            input
                .capture([OsString::from("oracle"), OsString::from(&huge)])
                .is_err()
        );
        assert_eq!(input.count, 2);
        assert_eq!(input.argument(1).unwrap(), huge.as_bytes());
        assert!(input.mode().is_err());
        assert!(input.allocated_bytes().unwrap() >= size_of::<Input>() + huge.len());
        assert!(
            input
                .capture([
                    OsString::from("oracle"),
                    OsString::from("--protocol-version")
                ])
                .is_err()
        );
        assert_eq!(input.argument(1).unwrap(), huge.as_bytes());
    }

    #[test]
    fn consumer_protocol_sha256_matches_independent_known_vectors() {
        assert_eq!(
            Digest::file(b""),
            Digest::parse(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
        );
        assert_eq!(
            Digest::file(b"abc"),
            Digest::parse(b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
        );
        assert_ne!(Digest::file(b"abc"), Digest::file(b"abc\0"));
    }

    #[test]
    fn consumer_protocol_output_overflow_is_sticky_and_preserves_prefix() {
        let mut row = Row::empty();
        row.write_str("prefix").unwrap();
        assert!(row.write_str(&"x".repeat(ROW_BYTES)).is_err());
        assert_eq!(row.initialized(), b"prefix");
        assert!(row.write_str("\n").is_err());
        assert!(row.publish().is_err());
        assert!(row.published().is_none());
    }

    #[test]
    fn consumer_protocol_output_requires_complete_once_only_record() {
        let mut row = Row::empty();
        assert!(row.publish().is_err());
        row.write_str("{}").unwrap();
        assert!(row.publish().is_err());
        row.write_str("\n").unwrap();
        // A supplied failed write record is pure model data; no stdout write.
        row.published = Some(WriteOutcome {
            requested: 3,
            returned: 1,
            errno: 0,
        });
        assert!(row.write_str("extra").is_err());
        assert!(row.publish().is_err());
        assert_eq!(row.initialized(), b"{}\n");
        assert_eq!(row.published().unwrap().returned, 1);
    }
}
