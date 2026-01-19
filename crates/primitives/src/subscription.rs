//! This module contains the core [`Subscription`] type that consumers of this API will use to
//! observe new events.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::mpsc;

/// A generic subscription type for event streams. It wraps an unbounded channel receiver
/// and implements [`futures::Stream`] for consuming events asynchronously.
#[derive(Debug)]
pub struct Subscription<T> {
    receiver: mpsc::UnboundedReceiver<T>,
}
impl<T> Subscription<T> {
    /// Returns the number of messages in the backlog for this subscription.
    pub fn backlog(&self) -> usize {
        self.receiver.len()
    }
}

impl<T> Subscription<T> {
    /// Creates a new subscription from an unbounded receiver.
    pub const fn from_receiver(receiver: mpsc::UnboundedReceiver<T>) -> Subscription<T> {
        Subscription { receiver }
    }
}

impl<T> futures::Stream for Subscription<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}
