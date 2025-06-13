//! Request-response abstraction for actor-based communication patterns.
//!
//! This module provides a generic [`Req`] type that encapsulates the common pattern
//! of sending a request with input data and receiving a response through a channel.
//! It's particularly useful in actor systems where you need to send a message and
//! wait for a response.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::oneshot;

/// A request-response pair that encapsulates input data with a response channel.
///
/// This type is useful for RPC-like patterns where you send some input data
/// and expect a single response back. It bundles the input with a channel
/// for receiving the response.
///
/// # Example
///
/// ```
/// use algebra::req::Req;
///
/// // Create a request with input data
/// let (req, response_receiver) = Req::new("hello".to_string());
///
/// // In an actor or handler:
/// let input = req.input();
/// let output = format!("{input} world");
/// req.resolve(output);
///
/// // The original caller can await the response:
/// // let result = response_receiver.await.unwrap();
/// ```
#[derive(Debug)]
pub struct Req<In, Out> {
    /// The input data for the request.
    input: In,

    /// Channel for sending the response back.
    response_sender: oneshot::Sender<Out>,
}

impl<In, Out> Req<In, Out> {
    /// Creates a new request with the given input.
    ///
    /// Returns both the [`Req`] object and a receiver channel that can be used
    /// to await the response.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data for the request
    ///
    /// # Returns
    ///
    /// A tuple containing:
    ///
    /// - The [`Req`] object to be sent to the handler
    /// - A [`oneshot::Receiver`] for receiving the response
    pub fn new(input: In) -> (Self, oneshot::Receiver<Out>) {
        let (response_sender, response_receiver) = oneshot::channel();

        let req = Self {
            input,
            response_sender,
        };

        (req, response_receiver)
    }

    /// Resolves the request by sending the output back through the response channel.
    ///
    /// This consumes the request object and sends the response. If the receiver
    /// has been dropped, the response is silently discarded.
    ///
    /// # Arguments
    ///
    /// * `output` - The response data to send back
    pub fn resolve(self, output: Out) {
        // Ignore errors - if the receiver was dropped, there's nothing we can do
        let _ = self.response_sender.send(output);
    }

    /// Returns a reference to the input data.
    ///
    /// This allows handlers to access the request data without consuming the
    /// [`Req`] object.
    pub const fn input(&self) -> &In {
        &self.input
    }

    /// Consumes the request and returns the input data by value.
    ///
    /// This is useful when you need to take ownership of the input data
    /// without requiring it to implement [`Clone`].
    ///
    /// Note: This consumes the request, so you cannot call [`Req::resolve`] after this.
    /// Use this method when you need to extract the input and handle the response
    /// separately.
    pub fn into_input(self) -> In {
        self.input
    }

    /// Consumes the request and returns both the input and response sender.
    ///
    /// This is useful when you need to take ownership of the input data without
    /// requiring it to implement [`Clone`], while still being able to send a response
    /// manually through the returned sender.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The input data by value
    /// - The response sender for manually sending the response
    ///
    /// # Example
    ///
    /// ```
    /// use algebra::req::Req;
    ///
    /// let (req, _receiver) = Req::new(String::from("hello"));
    /// let (input, response_sender) = req.into_parts();
    /// let output = format!("{input} world");
    /// let _ = response_sender.send(output);
    /// ```
    pub fn into_parts(self) -> (In, oneshot::Sender<Out>) {
        (self.input, self.response_sender)
    }

    /// Convenience method that applies a function to the input and resolves with the result.
    ///
    /// This is a shorthand for calling a function with the input and then resolving
    /// the request with the function's output.
    ///
    /// # Arguments
    ///
    /// * `f` - A function that transforms the input to the output
    ///
    /// # Example
    ///
    /// ```
    /// use algebra::req::Req;
    ///
    /// let (req, _receiver) = Req::new(42u32);
    /// req.dispatch(|input| input * 2); // Resolves with 84
    /// ```
    pub fn dispatch(self, f: impl FnOnce(&In) -> Out) {
        let output = f(&self.input);
        self.resolve(output);
    }

    /// Consumes the request, extracts the input by value, processes it with a function,
    /// and resolves the request with the result.
    ///
    /// This is useful when you need to take ownership of the input data without
    /// requiring it to implement [`Clone`]. The function receives the input by value
    /// and its return value is used as the response.
    ///
    /// # Arguments
    ///
    /// * `f` - A function that takes the input by value and returns the output
    ///
    /// # Example
    ///
    /// ```
    /// use algebra::req::Req;
    ///
    /// let (req, _receiver) = Req::new(String::from("hello"));
    /// req.resolve_with(|input| format!("{input} world")); // Resolves with "hello world"
    /// ```
    pub fn resolve_with(self, f: impl FnOnce(In) -> Out) {
        let output = f(self.input);
        let _ = self.response_sender.send(output);
    }
}

/// A future wrapper around a [`oneshot::Receiver`] for awaiting request responses.
///
/// This allows [`Req`] to be used in async contexts where you want to await
/// the response directly.
#[derive(Debug)]
pub struct ReqFuture<Out> {
    receiver: oneshot::Receiver<Out>,
}

impl<Out> ReqFuture<Out> {
    /// Creates a new [`ReqFuture`] from a receiver.
    pub const fn new(receiver: oneshot::Receiver<Out>) -> Self {
        Self { receiver }
    }
}

impl<Out> Future for ReqFuture<Out> {
    type Output = Result<Out, oneshot::error::RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver).poll(cx)
    }
}

/// Extension trait to make [`oneshot::Receiver`] directly awaitable as a [`Req`].
pub trait ReqExt<Out> {
    /// Converts the receiver into a future that can be awaited.
    fn into_req_future(self) -> ReqFuture<Out>;
}

impl<Out> ReqExt<Out> for oneshot::Receiver<Out> {
    fn into_req_future(self) -> ReqFuture<Out> {
        ReqFuture::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_req_basic_usage() {
        let (req, receiver) = Req::new("hello");

        // In a separate task, resolve the request
        tokio::spawn(async move {
            let response = format!("{} world", req.input());
            req.resolve(response);
        });

        // Await the response
        let result = receiver.await.unwrap();
        assert_eq!(result, "hello world");
    }

    #[tokio::test]
    async fn test_req_dispatch() {
        let (req, receiver) = Req::new(42i32);

        // Use dispatch to apply a function and resolve
        tokio::spawn(async move {
            req.dispatch(|input| input * 2);
        });

        // Await the response
        let result = receiver.await.unwrap();
        assert_eq!(result, 84);
    }

    #[tokio::test]
    async fn test_req_future_wrapper() {
        let (req, receiver) = Req::new("test");

        tokio::spawn(async move {
            req.resolve("response".to_string());
        });

        // Use the future wrapper
        let result = receiver.into_req_future().await.unwrap();
        assert_eq!(result, "response");
    }

    #[test]
    fn test_req_input_access() {
        let (req, _receiver): (Req<i32, String>, _) = Req::new(123);
        assert_eq!(*req.input(), 123);
    }

    #[tokio::test]
    async fn test_req_dropped_receiver() {
        let (req, receiver) = Req::new("test");

        // Drop the receiver
        drop(receiver);

        // Resolving should not panic
        req.resolve("response".to_string());
    }

    #[test]
    fn test_req_into_input() {
        // Test that into_input works without requiring Clone
        // Using a type that doesn't implement Clone to verify this
        struct NonClonableData {
            value: i32,
            name: String,
        }

        let input_data = NonClonableData {
            value: 42,
            name: "test".to_string(),
        };

        let (req, _receiver): (Req<NonClonableData, String>, _) = Req::new(input_data);

        // Extract the input without cloning
        let extracted = req.into_input();

        assert_eq!(extracted.value, 42);
        assert_eq!(extracted.name, "test");
    }

    #[tokio::test]
    async fn test_req_into_parts() {
        // Test that into_parts works without requiring Clone
        // Using a type that doesn't implement Clone to verify this
        struct NonClonableData {
            value: i32,
            name: String,
        }

        let input_data = NonClonableData {
            value: 123,
            name: "into_parts_test".to_string(),
        };

        let (req, receiver): (Req<NonClonableData, String>, _) = Req::new(input_data);

        // Extract both input and response sender without cloning
        let (extracted_input, response_sender) = req.into_parts();

        // Verify the input data is correct
        assert_eq!(extracted_input.value, 123);
        assert_eq!(extracted_input.name, "into_parts_test");

        // Send a response through the response sender
        let response = format!("processed: {}", extracted_input.value);
        let _ = response_sender.send(response);

        // Verify the response is received
        let result = receiver.await.unwrap();
        assert_eq!(result, "processed: 123");
    }
}
