//! This module contains the core [`Subscription`] type that consumers of this API will use to
//! observe new events.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::mpsc;

/// The primary type that consumers of this API will handle. It is created via one of the calls to
/// `BtcZmqClient::subscribe_*`. From there you should use it via it's [`futures::Stream`] API.
#[derive(Debug)]
pub struct Subscription<T> {
    receiver: mpsc::UnboundedReceiver<T>,
}

impl<T> Subscription<T> {
    /// Intentionally left private so as not to leak implementation details to consuming APIs.
    pub(crate) fn from_receiver(receiver: mpsc::UnboundedReceiver<T>) -> Subscription<T> {
        Subscription { receiver }
    }
}

impl<T> futures::Stream for Subscription<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}
