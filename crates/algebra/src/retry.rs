//! Retry mechanism inspired by Haskell's [RetryPolicyM](https://hackage.haskell.org/package/retry-0.9.3.1/docs/UnliftIO-Retry.html) combinator.
//!
//! This module provides a generalized retry strategy system that allows configuring
//! retry behavior through composable policies.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

/// Type alias for the error handler function to reduce type complexity.
pub type ErrorHandler<E> = Arc<dyn Fn(&E, usize) -> RetryAction + Send + Sync>;

/// Represents the action to take when an error occurs during retry attempts.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RetryAction {
    /// Continue retrying with the specified delay.
    Retry(Duration),

    /// Stop retrying and return the error.
    Stop,
}

/// A retry strategy that determines how to handle errors and when to retry.
///
/// This is similar to Haskell's [RetryPolicyM](https://hackage.haskell.org/package/retry-0.9.3.1/docs/UnliftIO-Retry.html), providing a way to configure
/// retry behavior through error classification and scheduling.
#[derive(Clone)]
pub struct Strategy<E> {
    /// Determines the action to take for a given error and retry attempt number.
    error_handler: ErrorHandler<E>,

    /// Maximum number of retry attempts (None for unlimited).
    max_retries: Option<usize>,
}

impl<E> std::fmt::Debug for Strategy<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Strategy")
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl<E> Strategy<E> {
    /// Creates a new retry strategy with the given error handler.
    ///
    /// This will retry indefinitely unless a maximum number of retries is set later with
    /// [`Self::with_max_retries`].
    pub fn new<F>(error_handler: F) -> Self
    where
        F: Fn(&E, usize) -> RetryAction + Send + Sync + 'static,
    {
        Self {
            error_handler: Arc::new(error_handler),
            max_retries: None,
        }
    }

    /// Sets the maximum number of retry attempts.
    pub const fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Creates a strategy that retries with exponential backoff.
    pub fn exponential_backoff(
        initial_delay: Duration,
        max_delay: Duration,
        multiplier: f64,
    ) -> Strategy<E>
    where
        E: Send + Sync + 'static,
    {
        Strategy::new(move |_error, attempt| {
            let delay_ms = (initial_delay.as_millis() as f64 * multiplier.powi(attempt as i32))
                .min(max_delay.as_millis() as f64) as u64;
            RetryAction::Retry(Duration::from_millis(delay_ms))
        })
    }

    /// Creates a strategy that retries with a fixed delay.
    pub fn fixed_delay(delay: Duration) -> Strategy<E>
    where
        E: Send + Sync + 'static,
    {
        Strategy::new(move |_error, _attempt| RetryAction::Retry(delay))
    }

    /// Creates a strategy that never retries.
    pub fn no_retry() -> Strategy<E>
    where
        E: Send + Sync + 'static,
    {
        Strategy::new(|_error, _attempt| RetryAction::Stop)
    }

    /// Combines this strategy with another using a logical OR.
    ///
    /// If this strategy says to stop, the other strategy is consulted.
    pub fn or<F>(self, other_handler: F) -> Strategy<E>
    where
        F: Fn(&E, usize) -> RetryAction + Send + Sync + 'static,
        E: Send + Sync + 'static,
    {
        let first_handler = self.error_handler;
        Strategy {
            error_handler: Arc::new(move |error, attempt| match first_handler(error, attempt) {
                RetryAction::Stop => other_handler(error, attempt),
                retry_action => retry_action,
            }),
            max_retries: self.max_retries,
        }
    }
}

/// Retry function that applies a strategy to a future-generating function.
///
/// This function takes a retry strategy and returns a function that can be applied
/// to a future generator to add retry behavior.
pub fn retry<A, E, Fut, Gen>(
    strategy: Strategy<E>,
) -> impl Fn(Gen) -> Pin<Box<dyn Future<Output = Result<A, E>> + Send>>
where
    A: Send + 'static,
    E: Send + 'static,
    Fut: Future<Output = Result<A, E>> + Send + 'static,
    Gen: FnMut() -> Fut + Send + 'static,
{
    move |mut generator: Gen| {
        let max_retries = strategy.max_retries;
        // Use Arc::clone to explicitly clone the Arc reference, not the trait object itself.
        // This avoids ambiguity since both Arc<T> and potentially the trait object could have
        // Clone.
        let error_handler = Arc::clone(&strategy.error_handler);

        Box::pin(async move {
            let mut attempt = 0;

            loop {
                match generator().await {
                    Ok(result) => return Ok(result),
                    Err(error) => {
                        // Check if we've exceeded max retries
                        if let Some(max_retries) = max_retries {
                            if attempt >= max_retries {
                                return Err(error);
                            }
                        }

                        // Determine what action to take
                        match error_handler(&error, attempt) {
                            RetryAction::Retry(delay) => {
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                            }
                            RetryAction::Stop => return Err(error),
                        }
                    }
                }
            }
        })
    }
}

/// A simplified retry function that takes the strategy and generator directly.
pub async fn retry_with<A, E, Fut, Gen>(strategy: Strategy<E>, mut generator: Gen) -> Result<A, E>
where
    A: Send + 'static,
    E: Send + 'static,
    Fut: Future<Output = Result<A, E>> + Send + 'static,
    Gen: FnMut() -> Fut + Send + 'static,
{
    let mut attempt = 0;

    loop {
        match generator().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                // Check if we've exceeded max retries
                if let Some(max_retries) = strategy.max_retries {
                    if attempt >= max_retries {
                        return Err(error);
                    }
                }

                // Determine what action to take
                match (strategy.error_handler)(&error, attempt) {
                    RetryAction::Retry(delay) => {
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    }
                    RetryAction::Stop => return Err(error),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    enum TestError {
        Retryable,
        Fatal,
    }

    #[tokio::test]
    async fn test_fixed_delay_strategy() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        const MAX_RETRIES: usize = 3;

        let strategy = Strategy::fixed_delay(Duration::from_millis(10)).with_max_retries(2);
        let success_msg = "success";

        let result = retry_with(strategy, move || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < MAX_RETRIES - 1 {
                    // fetch_add returns the previous value
                    Err(TestError::Retryable)
                } else {
                    Ok(success_msg)
                }
            }
        })
        .await;

        assert_eq!(result, Ok(success_msg));
        assert_eq!(counter.load(Ordering::SeqCst), MAX_RETRIES);
    }

    #[tokio::test]
    async fn test_error_classification() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let strategy = Strategy::new(|error: &TestError, _attempt| match error {
            TestError::Retryable => RetryAction::Retry(Duration::from_millis(1)),
            TestError::Fatal => RetryAction::Stop,
        });

        let result: Result<&str, TestError> = retry_with(strategy, move || {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Fatal)
            }
        })
        .await;

        assert_eq!(result, Err(TestError::Fatal));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_max_retries() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        const MAX_RETRIES: usize = 3;

        let strategy =
            Strategy::fixed_delay(Duration::from_millis(1)).with_max_retries(MAX_RETRIES);

        let result: Result<&str, TestError> = retry_with(strategy, move || {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Retryable)
            }
        })
        .await;

        assert_eq!(result, Err(TestError::Retryable));
        assert_eq!(counter.load(Ordering::SeqCst), MAX_RETRIES + 1); // Initial attempt + retries
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        const MAX_RETRIES: usize = 2;
        const INITIAL_DELAY: Duration = Duration::from_millis(1);
        const MAX_DELAY: Duration = Duration::from_millis(100);
        const MULTIPLIER: u32 = 2;

        let strategy = Strategy::exponential_backoff(INITIAL_DELAY, MAX_DELAY, MULTIPLIER as f64)
            .with_max_retries(MAX_RETRIES);

        let start = std::time::Instant::now();
        let success_msg = "success after retries";
        let result = retry_with(strategy, move || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < MAX_RETRIES {
                    Err(TestError::Retryable)
                } else {
                    Ok(success_msg)
                }
            }
        })
        .await;

        let elapsed = start.elapsed();
        assert_eq!(result, Ok(success_msg));
        assert_eq!(counter.load(Ordering::SeqCst), MAX_RETRIES + 1); // Initial attempt + retries

        assert!(elapsed >= INITIAL_DELAY * MULTIPLIER); // Should have waited at least
                                                        // `INITIAL_DELAY * MULTIPLIER` for the
                                                        // first retry
    }

    #[tokio::test]
    async fn test_retry_function_combinator() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        const MAX_RETRIES: usize = 2;

        let strategy = Strategy::fixed_delay(Duration::from_millis(1)).with_max_retries(2);

        // Create the retry combinator function
        let retry_fn = retry(strategy);

        // Use it with a generator function
        let result = retry_fn(move || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < MAX_RETRIES {
                    Err(TestError::Retryable)
                } else {
                    Ok("success from retry combinator")
                }
            }
        })
        .await;

        assert_eq!(result, Ok("success from retry combinator"));
        assert_eq!(counter.load(Ordering::SeqCst), MAX_RETRIES + 1); // Initial attempt + retries
    }

    #[tokio::test]
    async fn test_strategy_or_combinator() {
        const MAX_RETRIES: usize = 3;
        const FIRST_STRATEGY_DELAY: Duration = Duration::from_millis(1);
        const SECOND_STRATEGY_BASE_DELAY: u64 = 2;
        // Calculate expected delay: FIRST_STRATEGY_DELAY + 2^1 + 2^2 = 1ms + 2ms + 4ms = 7ms
        const MINIMUM_EXPECTED_DELAY: Duration = Duration::from_millis(
            FIRST_STRATEGY_DELAY.as_millis() as u64
                + SECOND_STRATEGY_BASE_DELAY.pow(1)
                + SECOND_STRATEGY_BASE_DELAY.pow(2),
        );

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        // First strategy: only retry on attempt 0, stop on attempt 1+
        let first_strategy = Strategy::new(|_error: &TestError, attempt| {
            if attempt == 0 {
                RetryAction::Retry(FIRST_STRATEGY_DELAY)
            } else {
                RetryAction::Stop
            }
        });

        // Second strategy: retry with exponential backoff
        let second_strategy = |_error: &TestError, attempt: usize| {
            let delay = Duration::from_millis(SECOND_STRATEGY_BASE_DELAY.pow(attempt as u32));
            RetryAction::Retry(delay)
        };

        // Combine strategies: if first says stop, consult second
        let combined_strategy = first_strategy
            .or(second_strategy)
            .with_max_retries(MAX_RETRIES);

        let start = std::time::Instant::now();
        let success_msg = "success with or combinator";

        let result = retry_with(combined_strategy, move || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < MAX_RETRIES {
                    Err(TestError::Retryable)
                } else {
                    Ok(success_msg)
                }
            }
        })
        .await;

        let elapsed = start.elapsed();
        assert_eq!(result, Ok(success_msg));
        assert_eq!(counter.load(Ordering::SeqCst), MAX_RETRIES + 1); // Initial attempt + retries

        // Should have waited the calculated minimum delay
        assert!(elapsed >= MINIMUM_EXPECTED_DELAY);
    }
}
