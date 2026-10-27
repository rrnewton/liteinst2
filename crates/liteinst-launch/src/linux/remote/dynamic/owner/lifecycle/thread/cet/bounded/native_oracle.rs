//! Full copied diagnostics; no proof or request constructor.
use super::*;
#[derive(Debug, Eq, PartialEq)]
struct Query {
    request: Request,
    bytes: Vec<u8>,
    requested_pointer: usize,
    returned_pointer: usize,
    returned_length: usize,
}
#[derive(Debug, Eq, PartialEq)]
struct Status {
    bytes: Vec<u8>,
    length: usize,
    open: Option<Request>,
    filesystem_request: Option<Request>,
    last_read: Option<Request>,
    filesystem: Option<i64>,
    complete: bool,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct CetRetainedSnapshot {
    queries: Vec<Option<Query>>,
    status: Vec<Status>,
    complete: bool,
    proof: Option<DisabledProof>,
}
impl BoundedCet {
    pub(in crate::linux::remote::dynamic::owner) fn test_retained_snapshot(
        &self,
    ) -> CetRetainedSnapshot {
        CetRetainedSnapshot {
            queries: self
                .queries
                .iter()
                .map(|q| {
                    q.as_ref().map(|v| Query {
                        request: v.request,
                        bytes: v.bytes.to_vec(),
                        requested_pointer: v.requested_pointer,
                        returned_pointer: v.returned_pointer,
                        returned_length: v.returned_length,
                    })
                })
                .collect(),
            status: self
                .status
                .iter()
                .map(|v| Status {
                    bytes: v.bytes.to_vec(),
                    length: v.length,
                    open: v.open,
                    filesystem_request: v.filesystem_request,
                    last_read: v.last_read,
                    filesystem: v.filesystem,
                    complete: v.complete,
                })
                .collect(),
            complete: self.complete,
            proof: self.proof,
        }
    }
}

impl CetRetainedSnapshot {
    pub(in crate::linux::remote::dynamic::owner) fn require_empty(&self) {
        assert_eq!(self.queries.len(), 7);
        assert!(self.queries.iter().all(Option::is_none));
        assert_eq!(self.status.len(), 2);
        for value in &self.status {
            assert_eq!(value.bytes.len(), MAX_STATUS_BYTES + 1);
            assert!(value.bytes.iter().all(|v| *v == 0));
            assert_eq!(
                (
                    value.length,
                    value.open,
                    value.filesystem_request,
                    value.last_read,
                    value.filesystem,
                    value.complete
                ),
                (0, None, None, None, None, false)
            );
        }
        assert!(!self.complete);
        assert_eq!(self.proof, None);
    }
}
