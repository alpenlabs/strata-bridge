//! This module contains constants related to how the transaction graph in the bridge is
//! constructed.
//!
//! These constants are integral to the graph i.e., changing them would change the nature of the
//! graph itself. These values must be known at compile-time.
use bitcoin::Amount;

/// The minimum value a segwit output script should have in order to be
/// broadcastable on today's Bitcoin network.
///
/// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
/// This function uses the default value of 0.00003 BTC/kB (3 sat/vByte).
pub const SEGWIT_MIN_AMOUNT: Amount = Amount::from_sat(330);

/// Default tag for the bridge.
pub const BRIDGE_TAG: &str = "ALPN";

/// Default denomination for each deposit to the bridge.
pub const BRIDGE_DENOMINATION: Amount = Amount::from_int_btc(10);
