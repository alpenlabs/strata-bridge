//! This module provides function definitions for all of the canonical boolean combinators.

/// Function definition for the ! boolean operation.
pub const fn not(a: bool) -> bool {
    !a
}

/// Function definition for the && boolean operation.
pub const fn and(a: bool, b: bool) -> bool {
    a && b
}

/// Function definition for the || boolean operation.
pub const fn or(a: bool, b: bool) -> bool {
    a || b
}

/// Function definition for the xor boolean operation.
pub const fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

/// Function definition for the negated && boolean operation.
pub const fn nand(a: bool, b: bool) -> bool {
    not(and(a, b))
}

/// Function definition for the negated || boolean operation.
pub const fn nor(a: bool, b: bool) -> bool {
    not(or(a, b))
}
