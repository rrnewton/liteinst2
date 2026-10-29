//! Optional RAW measurements on the existing fixed-work back-off path.
//! Printed endpoints remain tentative until unchanged post-output completion.
use super::super::throughput::{self as clock, Span, Timing, TimingError};
use super::*;

const TOTAL_OUTPUT_CAP: usize = OUTPUT_CAP + 16 * 1024;
const _: () = assert!(TOTAL_OUTPUT_CAP == 922_688 && TOTAL_OUTPUT_CAP < 1024 * 1024);
const FUNCTIONAL_SCOPE: &str = "# normal observer backoff elapsed; complete fixed work and raw callback ticks with a separate RAW timing appendix; no accuracy, cheap-off or 520-arm qualification";
const TIMING_SCOPE: &str = "# normal backoff elapsed v1; segmented guarded call-path and validated service wall nanoseconds; no subtraction, accuracy, speedup or continuous-throughput claim";
const TIMING_HEADER: &str = "kind,index,start_ns,end_ns";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Wire {
    Functional,
    Elapsed,
}
impl Wire {
    pub(super) fn labels(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Functional => (SCOPE, "normal-observer-backoff", "none"),
            Self::Elapsed => (
                FUNCTIONAL_SCOPE,
                "normal-observer-backoff-elapsed",
                "raw-appendix",
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Point {
    SetupStart,
    SetupEnd,
    BodyStart { first: usize, last: usize },
    BodyEnd { first: usize, last: usize },
    ServiceEnd,
}

// Private, statically dispatched choices only: NoTiming and Capture below.
// Passing the clock function does not call it. The original routes never read
// it, allocate timing storage, or validate a new timing population.
pub(super) trait Measurement {
    fn mark(&mut self, point: Point, read_clock: impl FnOnce() -> u64);
    fn output(&self, export: Export<'_>) -> String;
}
pub(super) struct NoTiming;
impl Measurement for NoTiming {
    fn mark(&mut self, _: Point, _: impl FnOnce() -> u64) {}
    fn output(&self, export: Export<'_>) -> String {
        super::output(export)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    New,
    Setup,
    Ready(usize),
    Body(usize),
    Done,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    Phase,
    Roles,
    Timing(TimingError),
}
struct Capture {
    phase: Phase,
    setup: Span,
    bodies: [Span; BLOCKS],
    service: Span,
}
impl Capture {
    fn new() -> Self {
        Self {
            phase: Phase::New,
            setup: Span::default(),
            bodies: [Span::default(); BLOCKS],
            service: Span::default(),
        }
    }
    fn record(&mut self, point: Point, read_clock: impl FnOnce() -> u64) -> Result<(), Error> {
        // Check the hook geometry before taking its timestamp. Each captured
        // body is exactly twelve existing helper pairs, never a split control.
        let next = match (self.phase, point) {
            (Phase::New, Point::SetupStart) => Phase::Setup,
            (Phase::Setup, Point::SetupEnd) => Phase::Ready(0),
            (Phase::Ready(b), Point::BodyStart { first, last })
                if b < BLOCKS && first == b * BLOCK / 2 && last == first + BLOCK / 2 =>
            {
                Phase::Body(b)
            }
            (Phase::Body(b), Point::BodyEnd { first, last })
                if b < BLOCKS && first == b * BLOCK / 2 && last == first + BLOCK / 2 =>
            {
                Phase::Ready(b + 1)
            }
            (Phase::Ready(BLOCKS), Point::ServiceEnd) => Phase::Done,
            _ => return Err(Error::Phase),
        };
        let stamp = read_clock();
        match (self.phase, point) {
            (Phase::New, Point::SetupStart) => self.setup.start = stamp,
            (Phase::Setup, Point::SetupEnd) => self.setup.end = stamp,
            (Phase::Ready(b), Point::BodyStart { .. }) => self.bodies[b].start = stamp,
            (Phase::Body(b), Point::BodyEnd { .. }) => self.bodies[b].end = stamp,
            (Phase::Ready(BLOCKS), Point::ServiceEnd) => {
                self.service = Span {
                    start: self.bodies[0].start,
                    end: stamp,
                };
            }
            _ => unreachable!("validated capture phase"),
        }
        self.phase = next;
        Ok(())
    }
    fn timing(&self) -> Result<Timing, Error> {
        if self.phase != Phase::Done {
            return Err(Error::Phase);
        }
        clock::validate_timing(self.setup, &self.bodies, self.service).map_err(Error::Timing)
    }
    fn append(
        &self,
        text: &mut String,
        k: usize,
        app_cpu: usize,
        controller_cpu: usize,
    ) -> Result<(), Error> {
        let timing = self.timing()?;
        if !matches!(k, 10 | 1000)
            || app_cpu >= 1024
            || controller_cpu >= 1024
            || app_cpu == controller_cpu
        {
            return Err(Error::Roles);
        }
        let begin = text.len();
        writeln!(text, "{TIMING_SCOPE}\n{TIMING_HEADER}").unwrap();
        timing_row(text, "setup", 0, self.setup);
        for (index, &body) in self.bodies.iter().enumerate() {
            timing_row(text, "body", index + 1, body);
        }
        timing_row(text, "service", 0, self.service);
        writeln!(text, "normal-observer-backoff-elapsed TIMING_COMPLETE k={k} app_cpu={app_cpu} controller_cpu={controller_cpu} clock=CLOCK_MONOTONIC_RAW units=ns timing_rows=130 setup_ns={} body_ns={} service_ns={}", timing.setup, timing.body, timing.service).unwrap();
        assert!(text.len() - begin <= 16 * 1024);
        Ok(())
    }
}
impl Measurement for Capture {
    fn mark(&mut self, point: Point, read_clock: impl FnOnce() -> u64) {
        self.record(point, read_clock)
            .expect("ordered complete elapsed hooks");
    }
    fn output(&self, export: Export<'_>) -> String {
        let (k, app_cpu, controller_cpu) = (export.f.k, export.app_cpu, export.controller_cpu);
        let mut text = super::output_with(export, Wire::Elapsed);
        self.append(&mut text, k, app_cpu, controller_cpu).unwrap();
        assert!(text.is_ascii() && text.len() <= TOTAL_OUTPUT_CAP);
        text
    }
}
fn timing_row(text: &mut String, kind: &str, index: usize, span: Span) {
    let begin = text.len();
    writeln!(text, "{kind},{index},{},{}", span.start, span.end).unwrap();
    assert!(text.len() - begin <= 64);
}

pub(crate) fn run(args: &[std::ffi::OsString]) {
    assert_eq!(
        args.len(),
        9,
        "normal-observer-backoff-elapsed K APP_CPU CONTROLLER_CPU CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
    );
    // Fixed inline storage is initialized before preparation/controller start.
    // Service-end is captured before encoding, but all old checks after encoding
    // and stdout write remain in run_measured. No success is granted here.
    super::run_measured(args, Capture::new());
}

#[cfg(test)]
mod tests;
