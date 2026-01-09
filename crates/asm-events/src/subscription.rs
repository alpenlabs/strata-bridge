//! Subscription type for ASM assignment streams.

// TODO:@prajwolrg: This is duplicated from btc-tracker/subscription. We should use the same
// subscription to avoid code duplication.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::mpsc;

/// Subscription wrapper for assignment events.
#[derive(Debug)]
pub struct Subscription<T> {
    receiver: mpsc::UnboundedReceiver<T>,
}

impl<T> Subscription<T> {
    /// Returns the number of messages in the backlog for this subscription.
    pub fn backlog(&self) -> usize {
        self.receiver.len()
    }

    pub(crate) const fn from_receiver(receiver: mpsc::UnboundedReceiver<T>) -> Subscription<T> {
        Subscription { receiver }
    }
}

impl<T> futures::Stream for Subscription<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}
