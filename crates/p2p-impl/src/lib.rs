//! Strata Bridge P2P.

pub mod bootstrap;
pub mod config;
pub mod constants;
pub mod message_handler;

pub use bootstrap::bootstrap;
pub use config::Configuration;
pub use message_handler::MessageHandler;

#[cfg(test)]
mod tests;
