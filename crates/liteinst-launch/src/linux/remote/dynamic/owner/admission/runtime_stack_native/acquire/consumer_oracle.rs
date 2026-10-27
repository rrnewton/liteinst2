//! Read-only feature views of actual installed acquisition owners, including
//! unstarted and failed prefixes. None of these projections is a certificate.
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission) struct ProfileAssociationView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) original_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) original_length: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) until: Instant,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct ProfileConsumerView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) diagnostic: &'a PreparedStackProfile,
    pub(in crate::linux::remote::dynamic::owner::admission) progress: &'a StackCaptureProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) eof: &'a [u8; 2],
    pub(in crate::linux::remote::dynamic::owner::admission) association:
        Option<ProfileAssociationView<'a>>,
    pub(in crate::linux::remote::dynamic::owner::admission) provenance: bool,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct ProfileKeyView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) payloads: [(usize, usize, usize); 3],
    pub(in crate::linux::remote::dynamic::owner::admission) original: (usize, usize),
    pub(in crate::linux::remote::dynamic::owner::admission) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) until: Instant,
    pub(in crate::linux::remote::dynamic::owner::admission) stack:
        &'a super::super::super::runtime_stack::metadata::StackDescriptor,
    pub(in crate::linux::remote::dynamic::owner::admission) metadata:
        &'a super::super::super::runtime_stack::metadata::StackMetadata,
    pub(in crate::linux::remote::dynamic::owner::admission) layout:
        &'a super::super::super::runtime_stack::access::PkuLayout,
    pub(in crate::linux::remote::dynamic::owner::admission) raw_layout: &'a PkuLayoutEvidence,
    pub(in crate::linux::remote::dynamic::owner::admission) initial_rsp: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a std::ops::Range<u64>,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct OperandProvenanceView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) origin: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission) execution: ExecutionId,
    pub(in crate::linux::remote::dynamic::owner::admission) profile: ProfileKeyView<'a>,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct OperandConsumerView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) diagnostic: &'a PreparedStackOperand,
    pub(in crate::linux::remote::dynamic::owner::admission) progress: &'a StackCaptureProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) pagemap_access: &'a PagemapAccess,
    pub(in crate::linux::remote::dynamic::owner::admission) eof: &'a [u8; 2],
    pub(in crate::linux::remote::dynamic::owner::admission) association:
        Option<&'a StackCaptureAssociation>,
    pub(in crate::linux::remote::dynamic::owner::admission) provenance:
        Option<OperandProvenanceView<'a>>,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct WordConsumerView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) capture: StackWordView<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) progress: &'a StackCaptureProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) eof: &'a [u8; 2],
}
impl PreparedStackProfileCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn consumer_view(
        &self,
    ) -> ProfileConsumerView<'_> {
        ProfileConsumerView {
            diagnostic: &self.diagnostic,
            progress: &self.progress,
            eof: &self.eof,
            association: self.association.as_ref().map(|v| ProfileAssociationView {
                stop: &v.stop,
                original_pointer: v.original_pointer,
                original_length: v.original_length,
                until: v.until,
            }),
            provenance: self.provenance,
        }
    }
}
impl PreparedStackOperandCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn consumer_view(
        &self,
    ) -> OperandConsumerView<'_> {
        OperandConsumerView {
            diagnostic: &self.diagnostic,
            progress: &self.progress,
            pagemap_access: &self.pagemap_access,
            eof: &self.eof,
            association: self.association.as_ref(),
            provenance: self.provenance.as_ref().map(|v| {
                let p = &v.profile;
                OperandProvenanceView {
                    origin: v.origin,
                    execution: v.execution,
                    profile: ProfileKeyView {
                        payloads: p.payloads.map(|b| (b.pointer, b.length, b.capacity)),
                        original: p.original,
                        stop: &p.stop,
                        until: p.until,
                        stack: &p.stack,
                        metadata: &p.metadata,
                        layout: &p.layout,
                        raw_layout: &p.raw_layout,
                        initial_rsp: p.initial_rsp,
                        island: &p.island,
                    },
                }
            }),
        }
    }
}
impl NativeStackWordCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn consumer_view(
        &self,
    ) -> WordConsumerView<'_> {
        WordConsumerView {
            capture: self.view(),
            progress: &self.progress,
            eof: &self.eof,
        }
    }
}

pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes()
-> Result<usize, LaunchError> {
    let mut bytes = 0_usize;
    for term in [
        size_of::<ProfileConsumerView<'_>>(),
        size_of::<OperandConsumerView<'_>>(),
        3 * size_of::<WordConsumerView<'_>>(),
        size_of::<OperandProvenanceView<'_>>(),
        size_of::<ProfileKeyView<'_>>(),
        size_of::<ProfileAssociationView<'_>>(),
    ] {
        bytes = bytes.checked_add(term).ok_or(LaunchError::Invalid(
            "consumer acquisition view size overflows",
        ))?;
    }
    Ok(bytes)
}
