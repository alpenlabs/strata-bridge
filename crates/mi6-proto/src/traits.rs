pub trait MI6Factory {
    fn produce(&self) -> Box<dyn MI6>;
}

pub trait MI6 {}
