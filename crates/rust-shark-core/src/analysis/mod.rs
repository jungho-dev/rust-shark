//! Lightweight, on-demand traffic analysis (anomaly heuristics).

pub mod anomaly;
pub mod threat;

pub use anomaly::{AnomalyAnnotation, AnomalyKind, AnomalySeverity, analyze};
pub use threat::{ThreatAnnotation, ThreatKind, ThreatTracker};
