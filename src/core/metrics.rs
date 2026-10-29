use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub total_sessions: AtomicU64,
    pub total_streams: AtomicU64,
    pub bytes_upstream: AtomicU64,
    pub bytes_downstream: AtomicU64,
    pub rejected_streams: AtomicU64,
}

#[derive(Clone, Copy)]
pub struct MetricsSnapshot {
    pub total_sessions: u64,
    pub total_streams: u64,
    pub bytes_upstream: u64,
    pub bytes_downstream: u64,
    pub rejected_streams: u64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_sessions: self.total_sessions.load(Ordering::Relaxed),
            total_streams: self.total_streams.load(Ordering::Relaxed),
            bytes_upstream: self.bytes_upstream.load(Ordering::Relaxed),
            bytes_downstream: self.bytes_downstream.load(Ordering::Relaxed),
            rejected_streams: self.rejected_streams.load(Ordering::Relaxed),
        }
    }
}
