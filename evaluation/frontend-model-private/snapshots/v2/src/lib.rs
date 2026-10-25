//! Private owned-ticket and bounded frontend controller model.
//! No TLS, return-address substitution, PMU, code publication or clock is implemented.
#![deny(warnings)]
#![forbid(unsafe_code)]

pub mod generation;
pub mod frontend;
