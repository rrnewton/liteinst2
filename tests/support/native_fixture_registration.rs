//! Closed default fixture registrations for the four pre-existing native entrypoints.
//! Invocations remain in their original support modules, preserving test identities.
macro_rules! register_native_fixture {
    (cache_truth) => {
        #[path = "../../tools/rapid-profiler/cache-work/truth.rs"]
        pub mod truth;
    };
    (tree_truth) => {
        use super::cache::truth as leaf;
        #[path = "../../tools/rapid-profiler/tree-work/truth.rs"]
        pub mod truth;
    };
    (strnlen_cases) => {
        #[path = "../../tools/rapid-profiler/strnlen-work/cases.rs"]
        pub mod cases;
    };
    (caller_bytes) => {
        #[path = "../../tools/rapid-profiler/normal-work/caller_bytes.rs"]
        pub mod caller_bytes;
    };
    (reference_bytes) => {
        pub use super::caller_bytes;
        #[path = "../../tools/rapid-profiler/normal-work/reference_bytes.rs"]
        pub mod bytes;
    };
}
