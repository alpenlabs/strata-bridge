fn dup<A: Clone>(
    s: impl Stream<Item = A> + Unpin + 'static,
) -> (impl Stream<Item = A> + Unpin, impl Stream<Item = A> + Unpin) {
    let fst_queue = Arc::new(Mutex::new(VecDeque::new()));
    let snd_queue = Arc::new(Mutex::new(VecDeque::new()));
    let upstream = Arc::new(Mutex::new(s));
    let fst_dup = Dup {
        self_queue: fst_queue.clone(),
        twin_queue: snd_queue.clone(),
        upstream: upstream.clone(),
    };

    let snd_dup = Dup {
        self_queue: snd_queue,
        twin_queue: fst_queue,
        upstream,
    };

    (fst_dup, snd_dup)
}
struct Dup<A> {
    self_queue: Arc<Mutex<VecDeque<A>>>,
    twin_queue: Arc<Mutex<VecDeque<A>>>,
    upstream: Arc<Mutex<dyn Stream<Item = A> + Unpin>>,
}
impl<A: Clone> Stream for Dup<A> {
    type Item = A;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut upstream = self.upstream.lock().unwrap(); // prevent deadlock
        let mut self_queue = self.self_queue.lock().unwrap();
        match self_queue.pop_front() {
            Some(a) => std::task::Poll::Ready(Some(a)),
            None => {
                let next = upstream.next().poll_unpin(cx);
                if let std::task::Poll::Ready(Some(a)) = &next {
                    self.twin_queue.lock().unwrap().push_back(a.clone());
                }
                next
            }
        }
    }
}
