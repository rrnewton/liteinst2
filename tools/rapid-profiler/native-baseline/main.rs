//! Fixed uninstrumented tree through the separately qualified private ABI stub.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]
use rapid_profiler::frontend_native::{LoadedCallTree, TreeContract};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[path = "../tree-work/native_call.rs"]
mod call;
#[path = "../ordinary-interval/tree/throughput/clocks.rs"]
mod clocks;
#[path = "../tree-work/collection.rs"]
mod collection;
// Reuse the complete independent input/operand truth; this executable uses
// only setup predicates. Full interpreter methods run in the native qualifier.
#[allow(dead_code)]
#[path = "../cache-work/truth.rs"]
mod leaf;
#[allow(dead_code)]
#[path = "../tree-work/truth.rs"]
mod truth;
use collection::{BLOCKS, CALLS, Results, input_index};
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const VALUES: [u64; 4] = [
    13455538007910626262,
    14448916110156114966,
    18114441086748040058,
    6122101979721109698,
];
#[repr(C, align(64))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Input([u8; 1152]);
fn inputs() -> [Input; 4] {
    std::array::from_fn(|i| {
        let mut out = Input([0xa5; 1152]);
        out.0[1088..].fill(0x5a);
        out.0[64..1088].copy_from_slice(&truth::input(truth::ALL[i / 2], SEEDS[i % 2]));
        out
    })
}
struct NativeTreeRun {
    call: call::NativeCall,
    input: Box<[Input; 4]>,
    expected: [Input; 4],
}
impl NativeTreeRun {
    fn load(candidate: &Path, trusted: &Path) -> Self {
        let bytes = expected_file(candidate, trusted);
        // SAFETY: fixed exact trusted ELF, sole actual caller/root-only entry,
        // bounded stack and immutable input, no signal/CET/nonlocal exit/fork/
        // file or alias writer/unload through the last real return.
        let owner = unsafe {
            LoadedCallTree::load(
                candidate,
                &bytes,
                c"call_tree_root",
                c"call_tree_child",
                TreeContract {
                    root_only_external_entry: true,
                    ordinary_ret_only: true,
                    no_active_cet: true,
                },
            )
        }
        .unwrap();
        truth::check_bytes(owner.root_code(), owner.callee_code()).unwrap();
        let call = unsafe { call::NativeCall::new(owner) };
        let owner = call.owner();
        let root = owner.certificate().root().entry();
        assert_eq!(owner.certificate().callee().entry(), root + 32);
        assert_eq!(
            owner.certificate().root().heads(),
            truth::ROOT_HEADS.map(|p| root + u64::from(p))
        );
        assert_eq!(
            owner.certificate().callee().heads(),
            truth::CHILD_HEADS.map(|p| root + 32 + u64::from(p))
        );
        let offset = usize::try_from(root - owner.source_range().0).unwrap();
        assert_eq!(
            &owner.original_source()[offset + 23..offset + 32],
            truth::GAP_BYTES
        );
        let expected = inputs();
        for (index, &value) in VALUES.iter().enumerate() {
            let case = truth::ALL[index / 2];
            let seed = SEEDS[index % 2];
            let cycle: &[u64] = if index < 2 { &[0, 4] } else { &[0, 4, 8] };
            let key = 0x9e37_79b9_7f4a_7c15_u64;
            let sum = (0..64).fold(0_u64, |sum, i| {
                sum.wrapping_add(seed ^ key.wrapping_mul(cycle[i % cycle.len()] + 1))
            });
            assert_eq!(value, (sum ^ key).wrapping_add(1));
            assert_eq!(value, truth::scalar(case, seed));
            let data = &expected[index].0[64..1088];
            assert_eq!(data, truth::input(case, seed));
            assert_eq!(u64::from_le_bytes(data[16..24].try_into().unwrap()), 64);
            for i in 0..64 {
                let at = usize::try_from(cycle[i % cycle.len()] * 64).unwrap();
                let next = cycle[(i + 1) % cycle.len()] * 64;
                assert_eq!(
                    u64::from_le_bytes(data[at..at + 8].try_into().unwrap()),
                    next
                );
                assert_eq!(
                    u64::from_le_bytes(data[at + 8..at + 16].try_into().unwrap()),
                    seed ^ key.wrapping_mul(cycle[i % cycle.len()] + 1)
                );
            }
        }
        Self {
            call,
            input: Box::new(expected.clone()),
            expected,
        }
    }
    fn invoke(&mut self, index: usize) -> u64 {
        // SAFETY: the exact inputs were validated before the loop and remain
        // immutable under sole ownership. The independently qualified private
        // stencil and retained DSO stay live; no SDK operation occurs here.
        unsafe { self.call.invoke(&self.input[index].0[64..1088]) }
    }
    fn postflight(&mut self) {
        self.call.verify_original();
        assert_eq!(*self.input, self.expected);
    }
}

fn pin(cpu: Option<usize>) -> usize {
    // Linux x86-64 affinity bitset, sized exactly as the native libc type.
    const WORDS: usize = std::mem::size_of::<libc::cpu_set_t>() / std::mem::size_of::<usize>();
    const BITS: usize = usize::BITS as usize;
    let mut allowed = [0_usize; WORDS];
    assert_eq!(
        unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(&allowed),
                allowed.as_mut_ptr().cast(),
            )
        },
        0
    );
    let selected = cpu.unwrap_or_else(|| {
        (0..allowed.len() * BITS)
            .find(|&n| allowed[n / BITS] & (1 << (n % BITS)) != 0)
            .expect("nonempty CPU affinity")
    });
    assert!(
        selected < allowed.len() * BITS && allowed[selected / BITS] & (1 << (selected % BITS)) != 0
    );
    let mut one = [0_usize; WORDS];
    one[selected / BITS] = 1 << (selected % BITS);
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&one), one.as_ptr().cast()) },
        0
    );
    assert_eq!(
        unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(&allowed),
                allowed.as_mut_ptr().cast(),
            )
        },
        0
    );
    assert_eq!(allowed, one);
    assert_eq!(unsafe { libc::sched_getcpu() }, selected as i32);
    selected
}

fn single_main() {
    let pid = std::process::id();
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(pid)
    );
    let tasks: Vec<_> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<_, _>>()
        .expect("complete task-directory observation");
    assert_eq!(tasks, [std::ffi::OsString::from(pid.to_string())]);
}

fn expected_file(candidate: &Path, expected: &Path) -> Vec<u8> {
    let mut file = File::open(expected).unwrap();
    let before = file.metadata().unwrap();
    let other = std::fs::metadata(candidate).unwrap();
    assert!(before.is_file() && other.is_file());
    assert_ne!(
        (before.dev(), before.ino()),
        (other.dev(), other.ino()),
        "independent expected file"
    );
    assert!((1..=1024 * 1024).contains(&before.len()));
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    assert_eq!(stamp(&before), stamp(&file.metadata().unwrap()));
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}

const HEADER: &str = "mode,block,call_first,call_last,roots,node_rows,sampled,closed,batches,events,reports,generation,history_prefix,gate_first,gate_last,completed_before,completed_after,conflict_population,conflict_retained,selection_error_numerator,selection_error_denominator,root_inclusive_instructions,root_exclusive_instructions,child_instructions,checksum";

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 3, "tree-native-baseline CANDIDATE TRUSTED");
    single_main();
    let cpu = pin(None);
    let resolution = clocks::resolution();
    let s0 = clocks::read();
    let mut run = NativeTreeRun::load(Path::new(&args[1]), Path::new(&args[2]));
    let mut collected = Results::new();
    let mut checksums = Vec::with_capacity(BLOCKS);
    let s1 = clocks::read();
    for block in 0..BLOCKS {
        let mut checksum = 0_u64;
        for call in 0..CALLS {
            let value = run.invoke(input_index(call));
            collected.record(block * CALLS + call, value);
            checksum = checksum.wrapping_add(value);
        }
        checksums.push(checksum);
    }
    let s2 = clocks::read();
    run.postflight();
    collected.complete(&VALUES, &checksums);
    let NativeTreeRun {
        call: _retained_call,
        input,
        expected: _,
    } = run;
    drop(input); // Same common input teardown boundary as the original SDK route.
    pin(Some(cpu));
    single_main();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{HEADER}").unwrap();
    for (block, checksum) in checksums.iter().enumerate() {
        let first = block * CALLS + 1;
        let last = first + 23;
        writeln!(
            out,
            "native,{block},{first},{last},24,0,0,0,0,0,0,,,,,,,14,,,,7968,144,7824,{checksum}"
        )
        .unwrap();
    }
    out.flush().unwrap();
    let s3 = clocks::read();
    let snapshots = [s0, s1, s2, s3];
    let m = clocks::metrics(&snapshots, resolution).expect("valid native consumer clock brackets");
    write!(out, "tree-comparison FUNCTIONAL_PASS mode=native blocks=64 roots=1536 calls=1536 originals=1536 installed_roots=0 node_rows=0 sampled=0 closed=0 batches=0 events=0 reports=0 epochs=0 actions=0 root_inclusive_instructions=509952 root_exclusive_instructions=9216 child_instructions=500736 input_unchanged=true records_joined=false clock_scope=matched-consumer collected_results=1536").unwrap();
    for (i, s) in snapshots.iter().enumerate() {
        write!(
            out,
            " s{i}_wall_before={} s{i}_cpu={} s{i}_wall_after={}",
            s.wall_before, s.cpu, s.wall_after
        )
        .unwrap();
    }
    writeln!(out," wall_resolution_ns={} cpu_resolution_ns={} whole_wall_lower_ns={} whole_wall_ns={} whole_cpu_ns={} loop_wall_lower_ns={} loop_wall_ns={} loop_cpu_ns={}",resolution.wall,resolution.cpu,m.whole_wall_lower,m.whole_wall_upper,m.whole_cpu,m.loop_wall_lower,m.loop_wall_upper,m.loop_cpu).unwrap();
    out.flush().unwrap();
    // The retained loader owns process-lived code even after this local borrow ends.
}
