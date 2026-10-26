//! Owner integration. Every temporary take is caught and restored before the
//! result or original unwind reaches the physical cleanup owner.
use super::*;

impl Owner {
    pub(in crate::linux::remote::dynamic::owner::admission) fn execute_runtime(
        &mut self,
        request: AdmissionRequest,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        if self.admission.is_some() {
            return Err(GateError::Refused(
                "runtime request conflicts with legacy admission custody",
            ));
        }
        if self.runtime.is_some() && matches!(&request, AdmissionRequest::StartRuntime { .. }) {
            return Err(GateError::Refused("runtime startup cannot be repeated"));
        }
        if self.runtime.is_none() {
            let AdmissionRequest::StartRuntime { initial, options } = request else {
                return Err(GateError::Refused("runtime admission is not initialized"));
            };
            let capture = runtime_capture::InitialCaptureProfile {
                max_vmas: options.capture.max_vmas,
                max_windows: options.capture.max_windows,
                max_window_bytes: options.capture.max_window_bytes,
                max_total_capture_bytes: options.capture.max_total_capture_bytes,
            };
            // Allocate without native reads. Custody is installed before the
            // original map capture, bootstrap effects, or source reads begin.
            self.runtime = Some(RuntimeOwner::allocate(
                RuntimeStartOptions {
                    capture,
                    limits: options.limits,
                },
                until,
            )?);
            let mut runtime = self.runtime.take().ok_or(GateError::Refused(
                "runtime startup allocation lost custody",
            ))?;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: the dedicated unsafe client entry supplies the same
                // immutable private writer/alias/bootstrap envelope. This new
                // request is private and contains no caller resume capability.
                unsafe { runtime.initialize(self, &initial) }
            }));
            self.runtime = Some(runtime);
            return match outcome {
                Ok(Ok(ready)) => Ok(AdmissionReply::RuntimeReady(
                    ready,
                    self.kernel_journal.reader(),
                )),
                Ok(Err(error)) => {
                    self.kernel_journal.fail_gate(&error);
                    Err(error)
                }
                Err(payload) => std::panic::resume_unwind(payload),
            };
        }
        let mut runtime = self
            .runtime
            .take()
            .ok_or(GateError::Refused("runtime request lost admission custody"))?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.execute(self, request, until)
        }));
        self.runtime = Some(runtime);
        match outcome {
            Ok(result) => {
                if let Err(error) = &result {
                    self.kernel_journal.fail_gate(error);
                }
                result
            }
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}
