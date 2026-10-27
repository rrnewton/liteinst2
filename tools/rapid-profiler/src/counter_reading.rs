//! Lossless counter endpoints and exact interval arithmetic, without acquisition.
//!
//! Arithmetic labels do not qualify an event, clock, invocation, synchronized
//! boundary or hardware estimate. Missing endpoints carry no inferred cause.
//! This module is independent of the existing live PMU and summary paths.

#![forbid(unsafe_code)]

/// The three original words from one counter reading, without interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterReading {
    pub value: u64,
    pub time_enabled: u64,
    pub time_running: u64,
}

/// Individually checked endpoint differences; `None` means that field regressed.
/// This type is reported only when both endpoints are present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckedDeltas {
    pub value: Option<u64>,
    pub time_enabled: Option<u64>,
    pub time_running: Option<u64>,
}

/// Monotonic differences whose time relationships have passed arithmetic checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterDelta {
    pub value: u64,
    pub time_enabled: u64,
    pub time_running: u64,
}

/// All observed arithmetic problems, rather than only the first one found.
/// A false field means no such problem was observed; it is not external proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArithmeticIssues {
    /// A smaller ending value; wrap, reset and other causes remain ambiguous.
    pub value_regressed: bool,
    pub time_enabled_regressed: bool,
    pub time_running_regressed: bool,
    pub start_running_exceeds_enabled: bool,
    pub end_running_exceeds_enabled: bool,
    /// Both time differences exist, but running exceeds enabled for the interval.
    pub running_delta_exceeds_enabled: bool,
    /// A positive count difference accompanies a zero running-time difference.
    /// No cause, including timer resolution or counter discontinuity, is inferred.
    pub value_changed_without_running: bool,
}

impl ArithmeticIssues {
    fn any(self) -> bool {
        self.value_regressed
            || self.time_enabled_regressed
            || self.time_running_regressed
            || self.start_running_exceeds_enabled
            || self.end_running_exceeds_enabled
            || self.running_delta_exceeds_enabled
            || self.value_changed_without_running
    }
}

/// Presence alone, not a diagnosis of why a read is missing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingEndpoints {
    Start,
    End,
    Both,
}

/// The exact, unreduced arithmetic estimate `delta_value * delta_enabled /
/// delta_running`. Construction requires a positive denominator.
///
/// Its two multiplicands are u64, so their product fits u128. Neither the
/// product nor the quotient is narrowed to u64, saturated or rounded to float.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactEstimate {
    numerator: u128,
    denominator: u64,
}

impl ExactEstimate {
    pub fn numerator(self) -> u128 {
        self.numerator
    }

    pub fn denominator(self) -> u64 {
        self.denominator
    }

    /// Integer part only; retain the remainder or ratio for a lossless result.
    pub fn quotient(self) -> u128 {
        self.numerator / u128::from(self.denominator)
    }

    /// Exact remainder, strictly smaller than the positive u64 denominator.
    pub fn remainder(self) -> u64 {
        (self.numerator % u128::from(self.denominator)) as u64
    }
}

/// Arithmetic classification only. No variant is an accuracy or quality pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arithmetic {
    /// Known endpoint inconsistencies are still reported when its peer is absent.
    /// Cross-endpoint regressions cannot be assessed in this variant.
    Missing {
        endpoints: MissingEndpoints,
        issues: ArithmeticIssues,
    },
    /// Every raw endpoint and individually computable difference remains retained.
    Rejected {
        issues: ArithmeticIssues,
        deltas: CheckedDeltas,
    },
    /// Both endpoints exist and are consistent, but no interval running time
    /// was observed. There is no estimate, including when the count is zero.
    ZeroRunning { delta: CounterDelta },
    /// Positive interval running time equals interval enabled time. This label
    /// describes these words; it does not attest non-multiplexed hardware use.
    FullRunning {
        delta: CounterDelta,
        estimate: ExactEstimate,
    },
    /// Positive interval running time is less than interval enabled time.
    /// Scaling a short interval is not thereby a qualified hardware estimate.
    Multiplexed {
        delta: CounterDelta,
        estimate: ExactEstimate,
    },
}

/// A fixed-size record that retains both original optional endpoints for every
/// classification. Construction never drops a row or changes an input word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterRecord {
    start: Option<CounterReading>,
    end: Option<CounterReading>,
    arithmetic: Arithmetic,
}

impl CounterRecord {
    pub fn new(start: Option<CounterReading>, end: Option<CounterReading>) -> Self {
        Self {
            start,
            end,
            arithmetic: classify(start, end),
        }
    }

    pub fn start(self) -> Option<CounterReading> {
        self.start
    }

    pub fn end(self) -> Option<CounterReading> {
        self.end
    }

    pub fn arithmetic(self) -> Arithmetic {
        self.arithmetic
    }
}

fn classify(start: Option<CounterReading>, end: Option<CounterReading>) -> Arithmetic {
    let mut issues = ArithmeticIssues {
        start_running_exceeds_enabled: start.is_some_and(|r| r.time_running > r.time_enabled),
        end_running_exceeds_enabled: end.is_some_and(|r| r.time_running > r.time_enabled),
        ..ArithmeticIssues::default()
    };
    let (start, end) = match (start, end) {
        (Some(start), Some(end)) => (start, end),
        (None, Some(_)) => {
            return Arithmetic::Missing {
                endpoints: MissingEndpoints::Start,
                issues,
            };
        }
        (Some(_), None) => {
            return Arithmetic::Missing {
                endpoints: MissingEndpoints::End,
                issues,
            };
        }
        (None, None) => {
            return Arithmetic::Missing {
                endpoints: MissingEndpoints::Both,
                issues,
            };
        }
    };
    let deltas = CheckedDeltas {
        value: end.value.checked_sub(start.value),
        time_enabled: end.time_enabled.checked_sub(start.time_enabled),
        time_running: end.time_running.checked_sub(start.time_running),
    };
    issues.value_regressed = deltas.value.is_none();
    issues.time_enabled_regressed = deltas.time_enabled.is_none();
    issues.time_running_regressed = deltas.time_running.is_none();
    issues.running_delta_exceeds_enabled = matches!(
        (deltas.time_enabled, deltas.time_running),
        (Some(enabled), Some(running)) if running > enabled
    );
    issues.value_changed_without_running = matches!(
        (deltas.value, deltas.time_running),
        (Some(value), Some(0)) if value != 0
    );
    let (value, time_enabled, time_running) =
        match (deltas.value, deltas.time_enabled, deltas.time_running) {
            (Some(value), Some(enabled), Some(running)) if !issues.any() => {
                (value, enabled, running)
            }
            _ => return Arithmetic::Rejected { issues, deltas },
        };
    let delta = CounterDelta {
        value,
        time_enabled,
        time_running,
    };
    if time_running == 0 {
        return Arithmetic::ZeroRunning { delta };
    }
    let estimate = ExactEstimate {
        numerator: u128::from(value) * u128::from(time_enabled),
        denominator: time_running,
    };
    if time_running == time_enabled {
        Arithmetic::FullRunning { delta, estimate }
    } else {
        Arithmetic::Multiplexed { delta, estimate }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(value: u64, time_enabled: u64, time_running: u64) -> CounterReading {
        CounterReading {
            value,
            time_enabled,
            time_running,
        }
    }

    #[test]
    fn full_running_is_an_interval_property_and_keeps_both_endpoints() {
        let start = reading(100, 20, 10);
        let end = reading(127, 50, 40);
        let record = CounterRecord::new(Some(start), Some(end));
        assert_eq!((record.start(), record.end()), (Some(start), Some(end)));
        let Arithmetic::FullRunning { delta, estimate } = record.arithmetic() else {
            panic!("expected full interval running time");
        };
        assert_eq!(
            delta,
            CounterDelta {
                value: 27,
                time_enabled: 30,
                time_running: 30
            }
        );
        // 27 observed events over 30/30 running/enabled units: 810/30 = 27.
        assert_eq!((estimate.numerator(), estimate.denominator()), (810, 30));
        assert_eq!((estimate.quotient(), estimate.remainder()), (27, 0));
    }

    #[test]
    fn multiplexed_estimates_preserve_integer_and_fractional_results() {
        for (start, end, numerator, denominator, quotient, remainder) in [
            (reading(100, 40, 20), reading(120, 80, 40), 800, 20, 40, 0),
            (reading(10, 20, 10), reading(17, 25, 13), 35, 3, 11, 2),
        ] {
            let record = CounterRecord::new(Some(start), Some(end));
            let Arithmetic::Multiplexed { estimate, .. } = record.arithmetic() else {
                panic!("expected multiplexed interval");
            };
            // Hand ratios: 20 * 40 / 20 = 40; 7 * 5 / 3 = 11 + 2/3.
            assert_eq!(
                (estimate.numerator(), estimate.denominator()),
                (numerator, denominator)
            );
            assert_eq!(
                (estimate.quotient(), estimate.remainder()),
                (quotient, remainder)
            );
            assert_eq!((record.start(), record.end()), (Some(start), Some(end)));
        }
    }

    #[test]
    fn zero_count_with_running_time_is_distinct_from_zero_running() {
        let start = reading(7, 10, 5);
        let available = CounterRecord::new(Some(start), Some(reading(7, 15, 10)));
        let Arithmetic::FullRunning { estimate, .. } = available.arithmetic() else {
            panic!("zero count is an available arithmetic value");
        };
        assert_eq!((estimate.numerator(), estimate.denominator()), (0, 5));
        assert_eq!((estimate.quotient(), estimate.remainder()), (0, 0));
        let stopped = CounterRecord::new(Some(start), Some(reading(7, 20, 5)));
        assert_eq!(
            stopped.arithmetic(),
            Arithmetic::ZeroRunning {
                delta: CounterDelta {
                    value: 0,
                    time_enabled: 10,
                    time_running: 0
                },
            }
        );
        let identical = CounterRecord::new(Some(start), Some(start));
        assert_eq!(
            identical.arithmetic(),
            Arithmetic::ZeroRunning {
                delta: CounterDelta {
                    value: 0,
                    time_enabled: 0,
                    time_running: 0
                },
            }
        );
    }

    #[test]
    fn missing_endpoints_keep_presence_and_known_facts_without_a_missing_cause() {
        let raw = reading(9, 2, 3);
        for (start, end, missing, start_issue, end_issue) in [
            (None, Some(raw), MissingEndpoints::Start, false, true),
            (Some(raw), None, MissingEndpoints::End, true, false),
            (None, None, MissingEndpoints::Both, false, false),
        ] {
            let record = CounterRecord::new(start, end);
            assert_eq!((record.start(), record.end()), (start, end));
            assert_eq!(
                record.arithmetic(),
                Arithmetic::Missing {
                    endpoints: missing,
                    issues: ArithmeticIssues {
                        start_running_exceeds_enabled: start_issue,
                        end_running_exceeds_enabled: end_issue,
                        ..ArithmeticIssues::default()
                    },
                }
            );
        }
    }

    #[test]
    fn regressions_remain_ambiguous_and_all_regressing_fields_are_visible() {
        let start = reading(u64::MAX - 1, 100, 90);
        let end = reading(3, 90, 85);
        let record = CounterRecord::new(Some(start), Some(end));
        assert_eq!((record.start(), record.end()), (Some(start), Some(end)));
        assert_eq!(
            record.arithmetic(),
            Arithmetic::Rejected {
                issues: ArithmeticIssues {
                    value_regressed: true,
                    time_enabled_regressed: true,
                    time_running_regressed: true,
                    ..ArithmeticIssues::default()
                },
                deltas: CheckedDeltas {
                    value: None,
                    time_enabled: None,
                    time_running: None
                },
            }
        );
        // Even plausible modular wrap from MAX-1 to 3 is not inferred.
        let record =
            CounterRecord::new(Some(reading(u64::MAX - 1, 10, 5)), Some(reading(3, 20, 10)));
        assert_eq!(
            record.arithmetic(),
            Arithmetic::Rejected {
                issues: ArithmeticIssues {
                    value_regressed: true,
                    ..ArithmeticIssues::default()
                },
                deltas: CheckedDeltas {
                    value: None,
                    time_enabled: Some(10),
                    time_running: Some(5)
                },
            }
        );
    }

    #[test]
    fn endpoint_and_interval_time_inconsistencies_refuse_estimates() {
        let record = CounterRecord::new(Some(reading(10, 10, 11)), Some(reading(11, 20, 21)));
        assert_eq!(
            record.arithmetic(),
            Arithmetic::Rejected {
                issues: ArithmeticIssues {
                    start_running_exceeds_enabled: true,
                    end_running_exceeds_enabled: true,
                    ..ArithmeticIssues::default()
                },
                deltas: CheckedDeltas {
                    value: Some(1),
                    time_enabled: Some(10),
                    time_running: Some(10)
                },
            }
        );
        let record = CounterRecord::new(Some(reading(10, 100, 10)), Some(reading(20, 110, 30)));
        assert_eq!(
            record.arithmetic(),
            Arithmetic::Rejected {
                issues: ArithmeticIssues {
                    running_delta_exceeds_enabled: true,
                    ..ArithmeticIssues::default()
                },
                deltas: CheckedDeltas {
                    value: Some(10),
                    time_enabled: Some(10),
                    time_running: Some(20)
                },
            }
        );
    }

    #[test]
    fn changed_count_without_running_time_is_retained_without_an_estimate() {
        let start = reading(2, 10, 5);
        let end = reading(4, 20, 5);
        let record = CounterRecord::new(Some(start), Some(end));
        assert_eq!((record.start(), record.end()), (Some(start), Some(end)));
        assert_eq!(
            record.arithmetic(),
            Arithmetic::Rejected {
                issues: ArithmeticIssues {
                    value_changed_without_running: true,
                    ..ArithmeticIssues::default()
                },
                deltas: CheckedDeltas {
                    value: Some(2),
                    time_enabled: Some(10),
                    time_running: Some(0)
                },
            }
        );
    }

    #[test]
    fn extreme_products_and_quotients_are_exact_beyond_u64() {
        // (2^64-1)^2 = 2^128 - 2^65 + 1, strictly less than u128::MAX.
        const SQUARE: u128 = 340282366920938463426481119284349108225;
        let start = Some(reading(0, 0, 0));
        let huge = CounterRecord::new(start, Some(reading(u64::MAX, u64::MAX, 1)));
        let Arithmetic::Multiplexed { estimate, .. } = huge.arithmetic() else {
            panic!("expected exact huge ratio");
        };
        assert_eq!((estimate.numerator(), estimate.denominator()), (SQUARE, 1));
        assert_eq!((estimate.quotient(), estimate.remainder()), (SQUARE, 0));
        let fractional = CounterRecord::new(start, Some(reading(u64::MAX, u64::MAX, u64::MAX - 1)));
        let Arithmetic::Multiplexed { estimate, .. } = fractional.arithmetic() else {
            panic!("expected exact huge fractional ratio");
        };
        // n^2 = (n-1)(n+1) + 1, with n=2^64-1.
        assert_eq!(
            (estimate.numerator(), estimate.denominator()),
            (SQUARE, 18446744073709551614)
        );
        assert_eq!(
            (estimate.quotient(), estimate.remainder()),
            (18446744073709551616, 1)
        );
        let full = CounterRecord::new(start, Some(reading(u64::MAX, u64::MAX, u64::MAX)));
        let Arithmetic::FullRunning { estimate, .. } = full.arithmetic() else {
            panic!("expected exact full-running maximum");
        };
        assert_eq!(
            (estimate.numerator(), estimate.denominator()),
            (SQUARE, u64::MAX)
        );
        assert_eq!(
            (estimate.quotient(), estimate.remainder()),
            (18446744073709551615, 0)
        );
    }
}
