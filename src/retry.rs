use std::time::Duration;

/// Exponential backoff policy for retryable RPC/NFS responses.
///
/// The high-level clients use this policy for conditions that are safe to
/// retry inside the client, such as NFSv3 `Jukebox` and NFSv4 `Delay` or
/// `Grace` responses. NFSv4 session recovery is handled separately because
/// replay safety depends on the operation and state involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_retries: u32,
    initial_delay: Duration,
    max_delay: Duration,
}

impl RetryPolicy {
    /// Creates a retry policy with capped exponential backoff.
    ///
    /// Retry `0` waits for `initial_delay`, retry `1` waits for twice that, and
    /// so on until `max_delay` is reached.
    pub fn new(max_retries: u32, initial_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            initial_delay,
            max_delay,
        }
    }

    /// Disables retries.
    pub fn disabled() -> Self {
        Self {
            max_retries: 0,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// Maximum number of retries after the initial attempt.
    pub fn max_retries(self) -> u32 {
        self.max_retries
    }

    /// Delay used before the first retry.
    pub fn initial_delay(self) -> Duration {
        self.initial_delay
    }

    /// Maximum delay between retry attempts.
    pub fn max_delay(self) -> Duration {
        self.max_delay
    }

    pub(crate) fn delay_for_retry(self, retry: u32) -> Option<Duration> {
        if retry >= self.max_retries {
            return None;
        }
        let multiplier = 1_u32.checked_shl(retry.min(31)).unwrap_or(u32::MAX);
        Some(
            self.initial_delay
                .saturating_mul(multiplier)
                .min(self.max_delay),
        )
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_caps_exponential_backoff() {
        let policy = RetryPolicy::new(4, Duration::from_millis(100), Duration::from_millis(250));

        assert_eq!(policy.delay_for_retry(0), Some(Duration::from_millis(100)));
        assert_eq!(policy.delay_for_retry(1), Some(Duration::from_millis(200)));
        assert_eq!(policy.delay_for_retry(2), Some(Duration::from_millis(250)));
        assert_eq!(policy.delay_for_retry(4), None);
    }
}
