//! Sequential OS-clock brackets, not simultaneous wall/CPU observations.
//! Clock resolution is reported; it is not an accuracy or minimum-duration bound.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) wall_before: u64,
    pub(super) cpu: u64,
    pub(super) wall_after: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Resolution {
    pub(super) wall: u64,
    pub(super) cpu: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Metrics {
    pub(super) whole_wall_lower: u64,
    pub(super) whole_wall_upper: u64,
    pub(super) whole_cpu: u64,
    pub(super) loop_wall_lower: u64,
    pub(super) loop_wall_upper: u64,
    pub(super) loop_cpu: u64,
}

fn normalized(status: libc::c_int, value: &libc::timespec) -> Option<u64> {
    if status != 0 {
        return None;
    }
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let nanos = u64::try_from(value.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

fn query(id: libc::clockid_t, resolution: bool) -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: both APIs receive one initialized, live timespec. No application
    // or callback state is borrowed here. Failure refuses without a retry.
    let status = unsafe {
        if resolution {
            libc::clock_getres(id, &mut value)
        } else {
            libc::clock_gettime(id, &mut value)
        }
    };
    normalized(status, &value).expect("valid OS-clock result and normalized nanoseconds")
}

/// Call before S0. Positive resolution is metadata, never a duration filter.
pub(super) fn resolution() -> Resolution {
    let result = Resolution {
        wall: query(libc::CLOCK_MONOTONIC, true),
        cpu: query(libc::CLOCK_PROCESS_CPUTIME_ID, true),
    };
    assert!(
        result.wall > 0 && result.cpu > 0,
        "positive clock resolutions"
    );
    result
}

/// The CPU observation lies between these sequential wall reads. No shared
/// wall/CPU epoch or simultaneous timestamp is asserted.
pub(super) fn read() -> Snapshot {
    let wall_before = query(libc::CLOCK_MONOTONIC, false);
    let cpu = query(libc::CLOCK_PROCESS_CPUTIME_ID, false);
    let wall_after = query(libc::CLOCK_MONOTONIC, false);
    assert!(wall_before <= wall_after, "ordered wall-clock bracket");
    Snapshot {
        wall_before,
        cpu,
        wall_after,
    }
}

fn span(start: Snapshot, end: Snapshot) -> Option<(u64, u64, u64)> {
    let lower = end.wall_before.checked_sub(start.wall_after)?;
    let upper = end.wall_after.checked_sub(start.wall_before)?;
    let cpu = end.cpu.checked_sub(start.cpu)?;
    if upper == 0 || cpu == 0 {
        return None;
    }
    Some((lower, upper, cpu))
}

/// S0 before source/input/load/preparation; S1 after setup before block 1;
/// S2 after block 64's retirement/drop; S3 after final checks and data flush.
/// Affinity/resolution setup and the final timing terminal are outside S0..S3.
/// All four immutable snapshots are checked, including the setup/final tails.
pub(super) fn metrics(s: &[Snapshot; 4], resolution: Resolution) -> Option<Metrics> {
    if resolution.wall == 0
        || resolution.cpu == 0
        || s.iter().any(|x| x.wall_before > x.wall_after)
        || s.windows(2)
            .any(|w| w[0].wall_after > w[1].wall_before || w[0].cpu > w[1].cpu)
    {
        return None;
    }
    let (whole_wall_lower, whole_wall_upper, whole_cpu) = span(s[0], s[3])?;
    let (loop_wall_lower, loop_wall_upper, loop_cpu) = span(s[1], s[2])?;
    Some(Metrics {
        whole_wall_lower,
        whole_wall_upper,
        whole_cpu,
        loop_wall_lower,
        loop_wall_upper,
        loop_cpu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ([Snapshot; 4], Resolution) {
        (
            [
                Snapshot {
                    wall_before: 100,
                    cpu: 1000,
                    wall_after: 110,
                },
                Snapshot {
                    wall_before: 200,
                    cpu: 1500,
                    wall_after: 220,
                },
                Snapshot {
                    wall_before: 500,
                    cpu: 2500,
                    wall_after: 540,
                },
                Snapshot {
                    wall_before: 700,
                    cpu: 4000,
                    wall_after: 750,
                },
            ],
            Resolution { wall: 1, cpu: 1 },
        )
    }

    #[test]
    fn timespec_conversion_preserves_boundaries_and_refuses_failures() {
        // Fabricated syscall outputs exercise the actual converter, no syscall.
        let value = libc::timespec {
            tv_sec: 7,
            tv_nsec: 9,
        };
        assert_eq!(normalized(0, &value), Some(7_000_000_009));
        assert_eq!(normalized(-1, &value), None);
        assert_eq!(normalized(1, &value), None);
        assert_eq!(
            normalized(
                0,
                &libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                }
            ),
            Some(0)
        );
        for value in [
            libc::timespec {
                tv_sec: -1,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: -1,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
            libc::timespec {
                tv_sec: 18_446_744_074,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 18_446_744_073,
                tv_nsec: 709_551_616,
            },
        ] {
            assert_eq!(normalized(0, &value), None);
        }
        assert_eq!(
            normalized(
                0,
                &libc::timespec {
                    tv_sec: 18_446_744_073,
                    tv_nsec: 709_551_615,
                }
            ),
            Some(u64::MAX)
        );
        assert_eq!(
            normalized(
                0,
                &libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 999_999_999,
                }
            ),
            Some(999_999_999)
        );
    }

    #[test]
    fn metrics_preserve_exact_brackets_zero_lower_and_independent_cpu() {
        let (s, resolution) = fixture();
        let expected = Metrics {
            whole_wall_lower: 590,
            whole_wall_upper: 650,
            whole_cpu: 3000,
            loop_wall_lower: 280,
            loop_wall_upper: 340,
            loop_cpu: 1000,
        };
        assert_eq!(metrics(&s, resolution), Some(expected));
        // Positive CPU deltas greater than wall are not relabelled or clipped.
        assert!(expected.whole_cpu > expected.whole_wall_upper);
        let mut touching = s;
        touching[2].wall_before = 220;
        touching[2].wall_after = 250;
        assert_eq!(
            metrics(&touching, resolution),
            Some(Metrics {
                loop_wall_lower: 0,
                loop_wall_upper: 50,
                ..expected
            })
        );
        let mut high = s;
        for x in &mut high {
            x.wall_before += u64::MAX - 750;
            x.wall_after += u64::MAX - 750;
            x.cpu += u64::MAX - 4000;
        }
        assert_eq!(metrics(&high, resolution), Some(expected));
        // Resolution is not an acceptance threshold for either duration.
        assert_eq!(
            metrics(
                &s,
                Resolution {
                    wall: u64::MAX,
                    cpu: u64::MAX
                }
            ),
            Some(expected)
        );
    }

    #[test]
    fn metrics_refuse_each_within_and_between_snapshot_order_violation() {
        let (s, resolution) = fixture();
        for i in 0..4 {
            let mut bad = s;
            bad[i].wall_before = bad[i].wall_after + 1;
            assert_eq!(metrics(&bad, resolution), None);
        }
        for i in 0..3 {
            let mut bad = s;
            bad[i + 1].wall_before = bad[i].wall_after - 1;
            assert!(bad[i + 1].wall_before <= bad[i + 1].wall_after);
            assert_eq!(metrics(&bad, resolution), None);
            let mut bad = s;
            bad[i + 1].cpu = bad[i].cpu - 1;
            assert_eq!(metrics(&bad, resolution), None);
        }
    }

    #[test]
    fn metrics_refuse_zero_resolution_nonpositive_regions_and_subtraction_underflow() {
        let (s, resolution) = fixture();
        for bad in [
            Resolution { wall: 0, cpu: 1 },
            Resolution { wall: 1, cpu: 0 },
        ] {
            assert_eq!(metrics(&s, bad), None);
        }
        let mut zero_wall = s;
        zero_wall[1].wall_before = 220;
        zero_wall[2].wall_before = 220;
        zero_wall[2].wall_after = 220;
        assert_eq!(metrics(&zero_wall, resolution), None);
        let mut zero_cpu = s;
        zero_cpu[2].cpu = zero_cpu[1].cpu;
        assert_eq!(metrics(&zero_cpu, resolution), None);
        let flat = [Snapshot {
            wall_before: 1,
            cpu: 1,
            wall_after: 1,
        }; 4];
        assert_eq!(metrics(&flat, resolution), None);
        // Actual checked span arithmetic refuses each negative difference.
        for field in 0..3 {
            let mut end = s[3];
            match field {
                0 => end.wall_before = s[0].wall_after - 1,
                1 => end.wall_after = s[0].wall_before - 1,
                2 => end.cpu = s[0].cpu - 1,
                _ => unreachable!(),
            }
            assert_eq!(span(s[0], end), None);
        }
    }
}
