//! DOCS

use std::{future::Future, pin::Pin};

use futures::{
    future::{self, BoxFuture},
    stream, FutureExt, Stream,
};

type AsyncConsumer<State> = Box<dyn FnMut(&State) -> BoxFuture<'static, ()>>;

/// A general state machine data structure that can be build from a config and state transition
/// function.
#[allow(missing_debug_implementations)]
pub struct StateMachine<
    Input,
    Config,
    State: Default,
    Output,
    Err,
    F: FnMut(&Config, &mut State, Input) -> Result<Output, Err>,
> {
    input_stream: Box<dyn Stream<Item = Input> + Unpin>,
    config: Config,
    state: State,
    stf: F,
    state_hook: AsyncConsumer<State>,
    pending_state_hook: Option<(BoxFuture<'static, ()>, Output)>,
}
impl<
        Input: 'static,
        Config,
        State: Default,
        Output,
        Err,
        F: FnMut(&Config, &mut State, Input) -> Result<Output, Err>,
    > StateMachine<Input, Config, State, Output, Err, F>
{
    /// Constructs a new state machine from its Config type and the state transition function.
    pub fn new(config: Config, stf: F) -> Self {
        StateMachine {
            input_stream: Box::new(stream::empty::<Input>()),
            config,
            state: State::default(),
            stf,
            state_hook: Box::new(|_| future::ready(()).boxed()),
            pending_state_hook: None,
        }
    }

    /// Restores a state machine from its Config type, it's state and the state transition function.
    pub fn restore(cfg: Config, state: State, stf: F) -> Self {
        StateMachine {
            input_stream: Box::new(stream::empty()),
            config: cfg,
            state,
            stf,
            state_hook: Box::new(|_| future::ready(()).boxed()),
            pending_state_hook: None,
        }
    }

    /// Gives us shared access to the internal Config value.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Gives us shared access to the internal State value.
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Feeds a single Input event into the StateMachine and returns the result.
    pub async fn feed(&mut self, input: Input) -> Result<Output, Err> {
        let res = (self.stf)(&self.config, &mut self.state, input);
        if res.is_ok() {
            (self.state_hook)(&self.state).await;
        }
        res
    }

    /// Attaches this StateMachine to an Input Stream which repeatedly feeds it.
    pub fn attach(&mut self, input_stream: impl Stream<Item = Input> + Unpin + 'static) {
        self.input_stream = Box::new(input_stream);
    }

    /// Registers an async State continuation to be called every time an Input event is accepted by
    /// the StateMachine.
    pub fn state_hook<R, Fut: Sync + Send + Future<Output = ()> + 'static>(
        &mut self,
        mut f: impl FnMut(&State) -> Fut + 'static,
    ) {
        self.state_hook = Box::new(move |s: &State| f(s).boxed());
    }
}

impl<
        Input: 'static,
        Config: Unpin,
        State: Default + Unpin,
        Output: Unpin,
        Err,
        F: FnMut(&Config, &mut State, Input) -> Result<Output, Err> + Unpin,
    > Stream for StateMachine<Input, Config, State, Output, Err, F>
{
    type Item = Result<Output, Err>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let StateMachine {
            input_stream,
            config,
            state,
            stf,
            state_hook,
            pending_state_hook,
            ..
        } = std::pin::Pin::into_inner(self);

        // First check if we still have to poll the State continuation.
        if let Some((mut fut, out)) = pending_state_hook.take() {
            return match fut.as_mut().poll(cx) {
                std::task::Poll::Ready(()) => std::task::Poll::Ready(Some(Ok(out))),
                std::task::Poll::Pending => {
                    pending_state_hook.replace((fut, out));
                    std::task::Poll::Pending
                }
            };
        }

        // Otherwise we can pull another event off of the upstream and process it.
        match Pin::new(input_stream).poll_next(cx) {
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Ready(Some(input)) => match stf(config, state, input) {
                Ok(output) => {
                    let mut state_hook_fut = state_hook(state);
                    match state_hook_fut.as_mut().poll(cx) {
                        std::task::Poll::Ready(()) => std::task::Poll::Ready(Some(Ok(output))),
                        std::task::Poll::Pending => {
                            *pending_state_hook = Some((state_hook_fut, output));
                            std::task::Poll::Pending
                        }
                    }
                }
                Err(err) => std::task::Poll::Ready(Some(Err(err))),
            },
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(test)]
mod state_machine_tests {
    use futures::stream::StreamExt;

    use super::*;
    #[tokio::test]
    async fn test_sm() {
        let mut sm = StateMachine::restore((), 0, test_stf);

        let inputs = stream::StreamExt::cycle(stream::iter(vec![false, true])).take(10);

        sm.attach(inputs);

        let transcript = sm
            .filter_map(|x| future::ready(x.ok()))
            .collect::<Vec<usize>>()
            .await;
        println!("{transcript:?}");
    }

    const fn test_stf(_cfg: &(), state: &mut usize, input: bool) -> Result<usize, ()> {
        if input {
            *state += 1;
        }
        Ok::<usize, ()>(*state)
    }
}
