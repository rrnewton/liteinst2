use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use perf_event_open_sys::{bindings as perf, perf_event_open};

const AMD_L2_REQUEST_MISS_CONFIG: u64 = 0x0964;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PerfReading {
    value: u64,
    time_enabled: u64,
    time_running: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CounterSnapshot {
    instructions: Option<PerfReading>,
    branches: Option<PerfReading>,
    l2_misses: Option<PerfReading>,
    pub(crate) timestamp: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CounterDelta {
    pub(crate) instructions: Option<u64>,
    pub(crate) branches: Option<u64>,
    pub(crate) l2_misses: Option<u64>,
    pub(crate) elapsed_ticks: u64,
}

impl CounterSnapshot {
    pub(crate) fn delta(self, start: Self) -> CounterDelta {
        CounterDelta {
            instructions: scaled_delta(self.instructions, start.instructions),
            branches: scaled_delta(self.branches, start.branches),
            l2_misses: scaled_delta(self.l2_misses, start.l2_misses),
            elapsed_ticks: self.timestamp.wrapping_sub(start.timestamp),
        }
    }
}

fn scaled_delta(end: Option<PerfReading>, start: Option<PerfReading>) -> Option<u64> {
    let (end, start) = end.zip(start)?;
    let value = end.value.wrapping_sub(start.value);
    let enabled = end.time_enabled.wrapping_sub(start.time_enabled);
    let running = end.time_running.wrapping_sub(start.time_running);
    if running == 0 {
        return None;
    }
    let scaled = u128::from(value)
        .saturating_mul(u128::from(enabled))
        .checked_div(u128::from(running))?;
    Some(scaled.min(u128::from(u64::MAX)) as u64)
}

struct PerfCounter(OwnedFd);

impl PerfCounter {
    fn open(event_type: u32, config: u64) -> Option<Self> {
        let mut attributes = perf::perf_event_attr {
            type_: event_type,
            config,
            ..Default::default()
        };
        attributes.size = core::mem::size_of_val(&attributes) as u32;
        attributes.read_format =
            u64::from(perf::PERF_FORMAT_TOTAL_TIME_ENABLED | perf::PERF_FORMAT_TOTAL_TIME_RUNNING);
        attributes.set_exclude_kernel(1);
        attributes.set_exclude_hv(1);
        attributes.set_exclude_guest(1);
        // SAFETY: attributes is initialized for a counting event on this thread.
        let fd = unsafe {
            perf_event_open(
                &mut attributes,
                0,
                -1,
                -1,
                perf::PERF_FLAG_FD_CLOEXEC as libc::c_ulong,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: perf_event_open returned exclusive ownership of this fd.
        Some(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn read(&self) -> Option<PerfReading> {
        let mut reading = PerfReading::default();
        // SAFETY: reading matches the selected three-u64 perf read format.
        let read = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                core::ptr::from_mut(&mut reading).cast(),
                core::mem::size_of_val(&reading),
            )
        };
        (read == core::mem::size_of_val(&reading) as isize).then_some(reading)
    }
}

#[derive(Default)]
pub(crate) struct CounterSet {
    instructions: Option<PerfCounter>,
    branches: Option<PerfCounter>,
    l2_misses: Option<PerfCounter>,
}

impl CounterSet {
    pub(crate) fn open() -> Self {
        Self {
            instructions: PerfCounter::open(
                perf::PERF_TYPE_HARDWARE,
                perf::PERF_COUNT_HW_INSTRUCTIONS.into(),
            ),
            branches: PerfCounter::open(
                perf::PERF_TYPE_HARDWARE,
                perf::PERF_COUNT_HW_BRANCH_INSTRUCTIONS.into(),
            ),
            l2_misses: amd_l2_event()
                .and_then(|config| PerfCounter::open(perf::PERF_TYPE_RAW, config)),
        }
    }

    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            instructions: self.instructions.as_ref().and_then(PerfCounter::read),
            branches: self.branches.as_ref().and_then(PerfCounter::read),
            l2_misses: self.l2_misses.as_ref().and_then(PerfCounter::read),
            // SAFETY: the crate is built only for x86-64 in Phase 2.
            timestamp: unsafe { core::arch::x86_64::_rdtsc() },
        }
    }
}

fn amd_l2_event() -> Option<u64> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
    let processor = cpuinfo.split("\n\n").next()?;
    let mut vendor = None;
    let mut family = None;
    for line in processor.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "vendor_id" => vendor = Some(value.trim()),
            "cpu family" => family = value.trim().parse::<u32>().ok(),
            _ => {}
        }
    }
    (vendor == Some("AuthenticAMD") && family == Some(26)).then_some(AMD_L2_REQUEST_MISS_CONFIG)
}

#[cfg(test)]
mod tests {
    use super::{CounterSnapshot, PerfReading, amd_l2_event};

    fn reading(value: u64, time_enabled: u64, time_running: u64) -> Option<PerfReading> {
        Some(PerfReading {
            value,
            time_enabled,
            time_running,
        })
    }

    #[test]
    fn counter_delta_scales_multiplexed_events_and_preserves_unavailable_ones() {
        let start = CounterSnapshot {
            instructions: reading(100, 20, 10),
            branches: None,
            l2_misses: reading(4, 20, 10),
            timestamp: 10,
        };
        let end = CounterSnapshot {
            instructions: reading(120, 40, 20),
            branches: reading(8, 40, 20),
            l2_misses: reading(9, 40, 20),
            timestamp: 18,
        };
        let delta = end.delta(start);
        assert_eq!(delta.instructions, Some(40));
        assert_eq!(delta.branches, None);
        assert_eq!(delta.l2_misses, Some(10));
        assert_eq!(delta.elapsed_ticks, 8);
    }

    #[test]
    fn a_counter_that_never_ran_is_unavailable() {
        let start = CounterSnapshot {
            instructions: reading(10, 20, 10),
            ..CounterSnapshot::default()
        };
        let end = CounterSnapshot {
            instructions: reading(10, 30, 10),
            ..CounterSnapshot::default()
        };
        assert_eq!(end.delta(start).instructions, None);
    }

    #[test]
    fn amd_l2_event_matches_the_perf_event_encoding() {
        if let Some(config) = amd_l2_event() {
            assert_eq!(config, 0x0964);
        }
    }
}
