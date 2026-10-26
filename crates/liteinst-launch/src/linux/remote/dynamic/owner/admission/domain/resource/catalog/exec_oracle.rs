//! Test-only exact inspection of every immutable source-set leaf.
use super::super::super::super::exec::oracle::{InspectionField, changed_snapshot, inspect};
use super::*;
type Check<T> = Box<dyn Fn(&T)>;

fn leaf(value: &ResourceBasis) -> Check<ResourceBasis> {
    let binding = value.binding;
    let policy = value.policy.clone();
    let images = value
        .images
        .iter()
        .map(|image| {
            (
                image.mapping_index,
                image.core_identity,
                image.snapshot.clone(),
                image.entries.clone(),
            )
        })
        .collect::<Vec<_>>();
    let maps = value.original_executables.clone();
    let totals = (value.candidates, value.decoded_starts, value.retained_bytes);
    let allocations = (
        value.images.as_ptr() as usize,
        value.images.capacity(),
        value.original_executables.as_ptr() as usize,
        value.original_executables.capacity(),
    );
    Box::new(move |actual| {
        assert_eq!(actual.binding, binding);
        assert_eq!(actual.policy, policy);
        assert_eq!(
            (
                actual.candidates,
                actual.decoded_starts,
                actual.retained_bytes
            ),
            totals
        );
        assert_eq!(
            (
                actual.images.as_ptr() as usize,
                actual.images.capacity(),
                actual.original_executables.as_ptr() as usize,
                actual.original_executables.capacity()
            ),
            allocations
        );
        assert_eq!(actual.original_executables, maps);
        assert_eq!(actual.images.len(), images.len());
        for (a, (index, identity, snapshot, entries)) in actual.images.iter().zip(&images) {
            assert_eq!((a.mapping_index, a.core_identity), (*index, *identity));
            inspect(InspectionField::SourceBytes, snapshot, &a.snapshot).unwrap();
            assert_eq!(
                inspect(
                    InspectionField::SourceBytes,
                    snapshot,
                    &changed_snapshot(&a.snapshot)
                ),
                Err(InspectionField::SourceBytes)
            );
            inspect(InspectionField::EntryFacts, entries, &a.entries).unwrap();
        }
    })
}
impl SourceCatalog {
    pub(in super::super::super) fn exec_oracle_check(&self) -> Check<Self> {
        let owner = self.owner;
        let totals = (self.retained_bytes, self.decoded_starts);
        let allocation = (self.leaves.as_ptr() as usize, self.leaves.capacity());
        let leaves = self.leaves.iter().map(leaf).collect::<Vec<_>>();
        Box::new(move |actual| {
            assert_eq!(actual.owner, owner);
            assert_eq!((actual.retained_bytes, actual.decoded_starts), totals);
            assert_eq!(
                (actual.leaves.as_ptr() as usize, actual.leaves.capacity()),
                allocation
            );
            assert_eq!(actual.leaves.len(), leaves.len());
            for (actual, check) in actual.leaves.iter().zip(&leaves) {
                check(actual);
            }
        })
    }
}
