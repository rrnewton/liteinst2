//! Original private native test identities; shared assertions live once.
use super::super::native_support::{Case, run};
mod failures;

#[test]
fn admitted_exec_native_first_user_and_retired_history_are_exact() {
    run(Case::Complete);
}
#[test]
fn admitted_exec_native_source_reply_refusal_keeps_new_mm_held() {
    run(Case::SourceRefusal);
}
#[test]
fn admitted_exec_native_errno_exit_never_mints_replacement() {
    run(Case::Errno);
}
