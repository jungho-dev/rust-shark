//! UI-agnostic inspector state (a reducer over IPC events + query results).
//! The ratatui rendering lives in the `rust-shark` binary's `inspect` frontend.

pub mod state;

pub use state::{DomainAgg, InspectorApp, ProcessAgg};
