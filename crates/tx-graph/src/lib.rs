//! This crate enables the creation and verification of a Glock transaction graph.

#![expect(
    rustdoc::private_intra_doc_links,
    reason = "Public docs link to pub(crate) helpers (e.g. fee surcharge math, anchor dust \
              value) for context. The links resolve when docs are built with \
              `--document-private-items`; in public-API rustdoc they degrade to plain \
              code-style text."
)]

pub mod fee;
pub mod game_graph;
pub mod musig_functor;
pub mod stake_graph;
pub mod transactions;
