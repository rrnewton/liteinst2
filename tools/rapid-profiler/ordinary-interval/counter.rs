//! Twelve serial original-only whole-API observations; no timing/cache accuracy.
use super::*;
use rapid_profiler::counter_probe::{CpuIdentity, ProbeReceipt, probe_current_thread_once};
use rapid_profiler::counter_reading::CounterReading;
use std::fmt::Write as _;
use std::io::Write as _;

#[path = "../cache-work/truth.rs"]
#[allow(dead_code)] // The native trace stage, not this driver, owns interpret/model checks.
pub mod truth;

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
#[repr(C, align(64))]
struct Input([u8; truth::INPUT_BYTES]);

fn csv(value: impl std::fmt::Display) -> String {
    format!("\"{}\"", value.to_string().replace('"', "\"\""))
}
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}
fn number(value: Option<u64>) -> String {
    value.map_or_else(String::new, |n| n.to_string())
}
fn endpoint(reading: Option<CounterReading>) -> String {
    match reading {
        Some(r) => format!("{},{},{}", r.value, r.time_enabled, r.time_running),
        None => ",,".into(),
    }
}
fn cpu(cpu: Option<CpuIdentity>) -> String {
    match cpu {
        Some(c) => format!(
            "{},{},{},{},{},{},{}",
            c.cpu,
            c.pid,
            c.tid,
            hex(&c.vendor),
            c.family,
            c.model,
            c.stepping
        ),
        None => ",,,,,,".into(),
    }
}
fn receipt(id: u64, r: &ProbeReceipt, counters: &mut File, operations: &mut File) {
    assert_eq!(id, r.external_id);
    let delta = r.full_running_delta.map(|d| CounterReading {
        value: d.value,
        time_enabled: d.time_enabled,
        time_running: d.time_running,
    });
    writeln!(
        counters,
        "{id},{},{},{},{},{},{},{},{},{}",
        number(r.event_id),
        endpoint(r.counters.start()),
        endpoint(r.counters.end()),
        endpoint(delta),
        cpu(r.cpu_before),
        cpu(r.cpu_after),
        hex(&r.requested_attributes),
        hex(&r.attributes_after_open),
        csv(format!("{:?}", r.issues))
    )
    .unwrap();
    for (index, op) in r.operations.iter().enumerate() {
        writeln!(
            operations,
            "{id},{index},{:?},{},{},{},{}",
            op.operation,
            op.syscall.result,
            op.syscall.errno.map_or_else(String::new, |n| n.to_string()),
            op.data_len,
            hex(&op.data[..op.data_len])
        )
        .unwrap();
    }
    counters.flush().unwrap();
    operations.flush().unwrap();
}
fn create(directory: &Path, name: &str, header: &str) -> File {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .unwrap();
    writeln!(file, "{header}").unwrap();
    file
}

pub(super) fn run(candidate: &Path, expected: &Path, output: &Path) -> i32 {
    single_main();
    let selected_cpu = pin(None);
    std::fs::create_dir(output).unwrap();
    let mut population = create(
        output,
        "population.csv",
        "external_id,seed,case,status,invoked,value,expected,pre_call_rsp,resumed_rsp,invocation_error",
    );
    let mut counters = create(
        output,
        "counters.csv",
        "external_id,event_id,start_value,start_enabled,start_running,end_value,end_enabled,end_running,delta_value,delta_enabled,delta_running,before_cpu,before_pid,before_tid,before_vendor,before_family,before_model,before_stepping,after_cpu,after_pid,after_tid,after_vendor,after_family,after_model,after_stepping,requested_attributes,attributes_after_open,issues",
    );
    let mut operations = create(
        output,
        "operations.csv",
        "external_id,index,operation,result,errno,data_len,data_hex",
    );
    let bytes = expected_file(candidate, expected);
    // SAFETY: unchanged trusted relocation-free leaf and ordinary loader contract.
    let owner =
        unsafe { LoadedIntegerLeaf::load(candidate, &bytes, c"cache_work_linked", CONTRACT) }
            .unwrap();
    truth::check_bytes(owner.code()).unwrap();
    let entry = owner.entry();
    assert_eq!(
        owner.certificate().heads(),
        truth::HEADS.map(|o| entry + u64::from(o))
    );
    assert_eq!(owner.certificate().returns(), [entry + 38]);
    let gate = CallGate::new(owner.certificate()).unwrap();
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    let readable = stack();
    let mut stopped = false;
    let (mut invoked, mut observed) = (0, 0);
    for (index, (seed, case)) in SEEDS
        .into_iter()
        .flat_map(|seed| truth::ALL.map(|case| (seed, case)))
        .enumerate()
    {
        let id = index as u64 + 1; // Complete population is fixed before any probe.
        let expected_value = truth::scalar(case, seed);
        if stopped {
            writeln!(
                population,
                "{id},{seed},{},UNRUN,false,,{expected_value},,,",
                case.name()
            )
            .unwrap();
            continue;
        }
        let input = Box::new(Input(truth::input(case, seed)));
        let before = input.0;
        assert_eq!(input.0.as_ptr() as usize % 64, 0);
        // Both original-owner checks remain INSIDE the counter's whole-API scope.
        // No prepare_original_call moved outside to claim a body-only interval.
        let observation = probe_current_thread_once(id, || unsafe {
            prep.invoke_original(input.0.as_ptr(), input.0.len(), &readable)
        });
        receipt(id, &observation.receipt, &mut counters, &mut operations);
        let mut value = None;
        let mut before_rsp = None;
        let mut resumed_rsp = None;
        let mut call_error = String::new();
        let actual_invocation = observation.invocation.is_some();
        let functional = match observation.invocation {
            Some(Ok(call)) => {
                invoked += 1;
                value = Some(call.value);
                before_rsp = Some(call.pre_call_rsp);
                resumed_rsp = Some(call.resumed_rsp);
                let valid = call.value == expected_value
                    && call.pre_call_rsp == call.resumed_rsp
                    && input.0 == before;
                if !valid {
                    call_error = "scalar, return RSP or complete input mismatch".into();
                }
                valid
            }
            Some(Err(e)) => {
                invoked += 1;
                call_error = format!("{e:?}");
                false
            }
            None => false,
        };
        let qualified = functional
            && observation.receipt.full_running_delta.is_some()
            && observation.receipt.issues.is_empty()
            && observation
                .receipt
                .cpu_before
                .is_some_and(|c| c.cpu as usize == selected_cpu);
        stopped = !qualified;
        observed += usize::from(qualified);
        let status = if qualified {
            "OBSERVED_FULL_RUNNING"
        } else {
            "FAILED"
        };
        writeln!(
            population,
            "{id},{seed},{},{status},{actual_invocation},{},{expected_value},{},{},{}",
            case.name(),
            number(value),
            number(before_rsp),
            number(resumed_rsp),
            csv(call_error)
        )
        .unwrap();
        population.flush().unwrap();
    }
    population.flush().unwrap();
    // The counter qualification is never used to waive invocation/source failures.
    single_main();
    pin(Some(selected_cpu));
    println!(
        "counter-probe required=12 invoked={invoked} observed_full_running={observed} status={} scope=whole-original-api hardware_accuracy=unqualified model11h_semantics=unqualified",
        if stopped { "FAILED" } else { "OBSERVED" }
    );
    if stopped { 2 } else { 0 }
}
