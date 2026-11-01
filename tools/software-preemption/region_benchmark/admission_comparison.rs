//! Same native work and Counter image, with explicitly different admission contracts.
use super::{
    Admission, Arm, CALLS, ClockMode, ENCOUNTERS, MEASUREMENTS, QUANTUM, RegionProgram, ResultRow,
    TAKEN, WARMUPS, affinity, batch, hook, pin, single_main, validate_schedule,
};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComparisonArm {
    Native,
    CounterPerCall,
    CounterBatch,
}
impl ComparisonArm {
    const ALL: [Self; 3] = [Self::Native, Self::CounterPerCall, Self::CounterBatch];

    fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::CounterPerCall => "counter-per-call",
            Self::CounterBatch => "counter-batch",
        }
    }

    fn worker(self) -> (Arm, Admission) {
        match self {
            Self::Native => (Arm::Native, Admission::PerCall),
            Self::CounterPerCall => (Arm::Counter, Admission::PerCall),
            Self::CounterBatch => (Arm::Counter, Admission::BoundedBatch),
        }
    }
}

fn order(text: &str) -> [ComparisonArm; 3] {
    use ComparisonArm::{CounterBatch as B, CounterPerCall as C, Native as N};
    match text {
        "native,counter-per-call,counter-batch" => [N, C, B],
        "native,counter-batch,counter-per-call" => [N, B, C],
        "counter-per-call,native,counter-batch" => [C, N, B],
        "counter-per-call,counter-batch,native" => [C, B, N],
        "counter-batch,native,counter-per-call" => [B, N, C],
        "counter-batch,counter-per-call,native" => [B, C, N],
        _ => panic!("required exact permutation of native,counter-per-call,counter-batch"),
    }
}

struct Row {
    arm: ComparisonArm,
    phase: &'static str,
    index: usize,
    status: &'static str,
    result: Option<ResultRow>,
}

fn roster(ordered: [ComparisonArm; 3]) -> Vec<Row> {
    let mut rows: Vec<_> = ComparisonArm::ALL
        .into_iter()
        .map(|arm| Row {
            arm,
            phase: "qualification",
            index: 0,
            status: "UNOBSERVED",
            result: None,
        })
        .collect();
    for arm in ordered {
        for index in 0..WARMUPS + MEASUREMENTS {
            rows.push(Row {
                arm,
                phase: if index < WARMUPS {
                    "warmup"
                } else {
                    "measured"
                },
                index: if index < WARMUPS {
                    index
                } else {
                    index - WARMUPS
                },
                status: "UNOBSERVED",
                result: None,
            });
        }
    }
    rows
}

fn render_rows(rows: &[Row], pid: u32) -> String {
    use std::fmt::Write;
    let mut csv = String::from(
        "pid,worker_tid,arm,phase,batch,status,calls,expected_encounters,expected_taken,elapsed_ns,checksum,clock_encounters,clock_taken,stops,remaining\n",
    );
    for row in rows {
        let values = row
            .result
            .as_ref()
            .map(|r| {
                let (encounters, taken, remaining) = r
                    .clock
                    .map(|w| {
                        (
                            w.encounters.to_string(),
                            w.counted.to_string(),
                            w.remaining.to_string(),
                        )
                    })
                    .unwrap_or_else(|| (String::new(), String::new(), String::new()));
                format!(
                    "{},{},{},{},{},{}",
                    r.elapsed_ns.map(|ns| ns.to_string()).unwrap_or_default(),
                    r.checksum,
                    encounters,
                    taken,
                    r.stops,
                    remaining
                )
            })
            .unwrap_or_else(|| ",,,,,".into());
        let tid = row
            .result
            .as_ref()
            .map(|r| r.tid.to_string())
            .unwrap_or_default();
        writeln!(
            csv,
            "{pid},{tid},{},{},{},{},{CALLS},{ENCOUNTERS},{TAKEN},{values}",
            row.arm.name(),
            row.phase,
            row.index,
            row.status
        )
        .unwrap();
    }
    csv
}

fn save_rows(output: &Path, rows: &[Row]) {
    std::fs::write(
        output.join("measurements.next"),
        render_rows(rows, std::process::id()),
    )
    .unwrap();
    std::fs::rename(
        output.join("measurements.next"),
        output.join("measurements.csv"),
    )
    .unwrap();
}

pub(super) fn run(text: &str, output: &Path) {
    single_main();
    let ordered = order(text);
    let cpus = affinity();
    assert_eq!(cpus.len(), 2, "exact externally reserved disjoint CPU pair");
    let mut rows = roster(ordered);
    save_rows(output, &rows);
    std::fs::write(
        output.join("summary.json"),
        "{\"status\":\"INCOMPLETE\",\"profile\":\"owned-clock-admission-throughput-v1\"}\n",
    )
    .unwrap();
    let mut active = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validate_schedule();
        // The same generated Counter image serves both admission arms. No
        // Stop instance or relabelled Stop measurement belongs to this cohort.
        let counter = RegionProgram::new_with_hook(ClockMode::Counter, hook);
        pin(cpus[0]);
        let mut index = 0;
        while index < rows.len() {
            active = Some(index);
            rows[index].status = "DISPATCHED";
            save_rows(output, &rows);
            let (arm, admission) = rows[index].arm.worker();
            let timed = rows[index].phase != "qualification";
            // The unchanged worker times batch admission and finish, while
            // acquire/reset, Ready/Go setup and final verification stay outside.
            let result = batch(&counter, arm, cpus[0], cpus[1], timed, None, admission);
            assert_eq!(result.stops, 0);
            assert_eq!(result.elapsed_ns.is_some(), timed);
            rows[index].result = Some(result);
            rows[index].status = "PASS";
            active = None;
            save_rows(output, &rows);
            index += 1;
        }
        assert_eq!(rows.len(), 204);
    }));
    if let Err(error) = outcome {
        if let Some(index) = active {
            rows[index].status = "FAILED";
        }
        save_rows(output, &rows);
        std::fs::write(
            output.join("summary.json"),
            "{\"status\":\"FAILED\",\"profile\":\"owned-clock-admission-throughput-v1\"}\n",
        )
        .unwrap();
        std::panic::resume_unwind(error);
    }
    std::fs::write(output.join("summary.json"), format!(
        "{{\"status\":\"PASS\",\"profile\":\"owned-clock-admission-throughput-v1\",\"order\":\"{text}\",\"controller_cpu\":{},\"worker_cpu\":{},\"qualification_rows\":3,\"warmup_rows\":9,\"measured_rows\":192,\"calls_per_batch\":{CALLS},\"encounters_per_lease\":{ENCOUNTERS},\"quantum\":{QUANTUM},\"stop_handoffs_per_batch\":0,\"publisher_validation\":false,\"full_state_after_callback\":false,\"performance_threshold\":false}}\n",
        cpus[0], cpus[1])).unwrap();
    println!(
        "preemption:region-admission-bench:3-qualified:9-warmups:192-measured:no-outlier-filter"
    );
}

#[cfg(test)]
mod tests {
    use super::super::ClockWords;
    use super::*;

    #[test]
    fn labels_bind_distinct_admission_to_one_counter_mode() {
        let actual = ComparisonArm::ALL.map(|arm| (arm.name(), arm.worker()));
        assert_eq!(
            actual,
            [
                ("native", (Arm::Native, Admission::PerCall)),
                ("counter-per-call", (Arm::Counter, Admission::PerCall)),
                ("counter-batch", (Arm::Counter, Admission::BoundedBatch)),
            ]
        );
        for invalid in [
            "native,counter,stop",
            "native,counter-batch,counter-batch",
            "counter-per-call,native",
            "native,counter-per-call,counter-batch,stop",
        ] {
            assert!(std::panic::catch_unwind(|| order(invalid)).is_err());
        }
    }

    #[test]
    fn every_order_retains_complete_qualification_and_timing_denominator() {
        // Enumerate all distinct triples independently of the six parser arms.
        let mut checked = 0;
        for a in ComparisonArm::ALL {
            for b in ComparisonArm::ALL {
                for c in ComparisonArm::ALL {
                    if a == b || a == c || b == c {
                        continue;
                    }
                    let text = format!("{},{},{}", a.name(), b.name(), c.name());
                    let rows = roster(order(&text));
                    assert_eq!(rows.len(), 204);
                    for (row, arm) in rows[..3].iter().zip(ComparisonArm::ALL) {
                        assert_eq!((row.arm, row.phase, row.index), (arm, "qualification", 0));
                    }
                    let mut rest = rows[3..].iter();
                    for arm in [a, b, c] {
                        for (phase, count) in [("warmup", 3), ("measured", 64)] {
                            for index in 0..count {
                                let row = rest.next().unwrap();
                                assert_eq!((row.arm, row.phase, row.index), (arm, phase, index));
                            }
                        }
                    }
                    assert!(rest.next().is_none());
                    assert!(
                        rows.iter()
                            .all(|row| row.status == "UNOBSERVED" && row.result.is_none())
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 6);
    }

    #[test]
    fn csv_retains_exact_labels_clocks_and_incomplete_rows() {
        let rows = [
            Row {
                arm: ComparisonArm::Native,
                phase: "qualification",
                index: 0,
                status: "PASS",
                result: Some(ResultRow {
                    elapsed_ns: None,
                    checksum: 24576,
                    stops: 0,
                    clock: None,
                    tid: 102,
                }),
            },
            Row {
                arm: ComparisonArm::CounterPerCall,
                phase: "warmup",
                index: 1,
                status: "PASS",
                result: Some(ResultRow {
                    elapsed_ns: Some(9876),
                    checksum: 24576,
                    stops: 0,
                    clock: Some(ClockWords {
                        saved_rcx: 0,
                        encounters: 30720,
                        counted: 22528,
                        remaining: 64,
                    }),
                    tid: 103,
                }),
            },
            Row {
                arm: ComparisonArm::CounterBatch,
                phase: "measured",
                index: 63,
                status: "PASS",
                result: Some(ResultRow {
                    elapsed_ns: Some(1234),
                    checksum: 24576,
                    stops: 0,
                    clock: Some(ClockWords {
                        saved_rcx: 0,
                        encounters: 30720,
                        counted: 22528,
                        remaining: 64,
                    }),
                    tid: 104,
                }),
            },
            Row {
                arm: ComparisonArm::CounterBatch,
                phase: "measured",
                index: 0,
                status: "FAILED",
                result: None,
            },
            Row {
                arm: ComparisonArm::CounterPerCall,
                phase: "measured",
                index: 0,
                status: "UNOBSERVED",
                result: None,
            },
        ];
        assert_eq!(
            render_rows(&rows, 101),
            concat!(
                "pid,worker_tid,arm,phase,batch,status,calls,expected_encounters,expected_taken,elapsed_ns,checksum,clock_encounters,clock_taken,stops,remaining\n",
                "101,102,native,qualification,0,PASS,2048,30720,22528,,24576,,,0,\n",
                "101,103,counter-per-call,warmup,1,PASS,2048,30720,22528,9876,24576,30720,22528,0,64\n",
                "101,104,counter-batch,measured,63,PASS,2048,30720,22528,1234,24576,30720,22528,0,64\n",
                "101,,counter-batch,measured,0,FAILED,2048,30720,22528,,,,,,\n",
                "101,,counter-per-call,measured,0,UNOBSERVED,2048,30720,22528,,,,,,\n",
            )
        );
    }
}
