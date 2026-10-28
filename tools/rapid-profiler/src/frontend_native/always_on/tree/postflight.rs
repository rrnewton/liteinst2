//! Preserve the first gate refusal while attempting both safe postflight checks.

pub(super) fn check<T, E>(
    pending: Result<T, E>,
    source: impl FnOnce() -> Result<(), E>,
    input: impl FnOnce() -> Result<(), E>,
) -> Result<T, E> {
    // Neither refusal skips the other safe check. Pending owns its gate flight
    // throughout both checks; any later error/unwind drops it without commit.
    let source = source();
    let input = input();
    let pending = pending?;
    source?;
    input?;
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::super::{Cause, GateError, SiteError, TreeError, error};
    use super::check;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[test]
    fn installed_gate_error_survives_both_postflight_refusals() {
        for (source_fails, input_fails) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let order = RefCell::new(Vec::new());
            let result = check::<(), TreeError>(
                Err(TreeError::Gate(GateError::Completion)),
                || {
                    order.borrow_mut().push("source");
                    if source_fails {
                        Err(TreeError::Site(SiteError::Correspondence))
                    } else {
                        Ok(())
                    }
                },
                || {
                    order.borrow_mut().push("input");
                    if input_fails {
                        Err(TreeError::Bridge(error(Cause::Invariant)))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(matches!(
                result,
                Err(TreeError::Gate(GateError::Completion))
            ));
            assert_eq!(*order.borrow(), ["source", "input"]);
        }
    }

    #[test]
    fn original_gate_error_survives_both_postflight_refusals() {
        for (source_fails, input_fails) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let order = RefCell::new(Vec::new());
            let result = check::<(), SiteError>(
                Err(SiteError::Gate(GateError::Identity)),
                || {
                    order.borrow_mut().push("source");
                    if source_fails {
                        Err(SiteError::Correspondence)
                    } else {
                        Ok(())
                    }
                },
                || {
                    order.borrow_mut().push("input");
                    if input_fails {
                        Err(SiteError::Correspondence)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(matches!(result, Err(SiteError::Gate(GateError::Identity))));
            assert_eq!(*order.borrow(), ["source", "input"]);
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Failure {
        Source,
        Input,
    }
    // An ownership-only witness; this is not a fabricated native Pending or RET.
    #[derive(Debug)]
    struct Owned(Rc<Cell<usize>>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn successful_gate_retains_pending_until_both_checks_then_refuses_or_transfers() {
        for (source_fails, input_fails) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let drops = Rc::new(Cell::new(0));
            let order = RefCell::new(Vec::new());
            let result = check(
                Ok(Owned(Rc::clone(&drops))),
                || {
                    assert_eq!(drops.get(), 0);
                    order.borrow_mut().push("source");
                    if source_fails {
                        Err(Failure::Source)
                    } else {
                        Ok(())
                    }
                },
                || {
                    assert_eq!(drops.get(), 0);
                    order.borrow_mut().push("input");
                    if input_fails {
                        Err(Failure::Input)
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(*order.borrow(), ["source", "input"]);
            if source_fails || input_fails {
                assert_eq!(
                    result.unwrap_err(),
                    if source_fails {
                        Failure::Source
                    } else {
                        Failure::Input
                    }
                );
                assert_eq!(drops.get(), 1);
            } else {
                let held = result.unwrap();
                assert_eq!(drops.get(), 0);
                drop(held);
                assert_eq!(drops.get(), 1);
            }
        }
    }

    #[test]
    fn postflight_unwind_drops_pending_without_returning_success() {
        let drops = Rc::new(Cell::new(0));
        let entered_input = Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = check::<Owned, Failure>(
                Ok(Owned(Rc::clone(&drops))),
                || panic!("postflight source unwind"),
                || {
                    entered_input.set(true);
                    Ok(())
                },
            );
        }));
        assert!(result.is_err());
        assert_eq!(drops.get(), 1);
        assert!(!entered_input.get());
    }
}
