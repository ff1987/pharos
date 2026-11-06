use std::sync::Mutex;
use std::time::Duration;

use std::sync::{Arc, RwLock};

use pharos_proto::{BytePacer, LimitsConfig};

use crate::state::Metrics;

struct BucketState {
    tokens: f64,
    updated: tokio::time::Instant,
    primed: bool,
}

struct Bucket {
    state: Mutex<BucketState>,
}

impl Bucket {
    fn new() -> Self {
        Self {
            state: Mutex::new(BucketState {
                tokens: 0.0,
                updated: tokio::time::Instant::now(),
                primed: false,
            }),
        }
    }

    async fn take(&self, n: usize, rate: u64, metrics: &Metrics, direction: &'static str) {
        if rate == 0 || n == 0 {
            return;
        }
        let mut left = n as f64;
        loop {
            let wait = {
                let mut state = self.state.lock().expect("bandwidth bucket");
                let now = tokio::time::Instant::now();
                if !state.primed {
                    state.tokens = rate as f64;
                    state.updated = now;
                    state.primed = true;
                } else {
                    let elapsed = now.saturating_duration_since(state.updated).as_secs_f64();
                    state.updated = now;
                    state.tokens = (state.tokens + elapsed * rate as f64).min(rate as f64);
                }
                if state.tokens >= left {
                    state.tokens -= left;
                    return;
                }
                if state.tokens > 0.0 {
                    left -= state.tokens;
                    state.tokens = 0.0;
                }
                Duration::from_secs_f64(left / rate as f64)
            };
            if wait.is_zero() {
                continue;
            }
            metrics
                .throttle_events
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if wait >= Duration::from_millis(20) {
                tracing::info!(
                    direction,
                    rate,
                    bytes = n,
                    wait_ms = wait.as_millis() as u64,
                    "throttling client bandwidth"
                );
            } else {
                tracing::debug!(
                    direction,
                    rate,
                    bytes = n,
                    wait_ms = wait.as_millis() as u64,
                    "throttling client bandwidth"
                );
            }
            tokio::time::sleep(wait).await;
        }
    }
}

/// Shared inbound and outbound limiters for one authenticated client.
pub struct ClientPace {
    inbound: Bucket,
    outbound: Bucket,
    limits: Arc<RwLock<LimitsConfig>>,
    metrics: Arc<Metrics>,
}

impl ClientPace {
    pub fn new(limits: Arc<RwLock<LimitsConfig>>, metrics: Arc<Metrics>) -> Self {
        Self {
            inbound: Bucket::new(),
            outbound: Bucket::new(),
            limits,
            metrics,
        }
    }
}

impl BytePacer for ClientPace {
    async fn pace_from_tcp(&self, n: usize) {
        let rate = self.limits.read().expect("limits").bytes_in_per_sec;
        self.inbound.take(n, rate, &self.metrics, "in").await;
    }

    async fn pace_to_tcp(&self, n: usize) {
        let rate = self.limits.read().expect("limits").bytes_out_per_sec;
        self.outbound.take(n, rate, &self.metrics, "out").await;
    }
}
