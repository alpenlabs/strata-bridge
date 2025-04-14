use std::time::Duration;

pub(crate) const STARTUP_DELAY: Duration = Duration::from_secs(10);

pub(crate) const DEFAULT_THREAD_COUNT: u8 = 4;

pub(crate) const DEFAULT_THREAD_STACK_SIZE: usize = 100 * 1024 * 1024;
