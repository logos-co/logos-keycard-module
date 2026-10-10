//! keycard_module: a bare Keycard behind `logos.signer/1`, over PC/SC. It lists the accounts the
//! person offered from the card, and signs the hashes the signer manager computes once the card's
//! PIN, typed in the signer, opens it. The keys stay on the card; the PIN only passes through.
//!
//! The core is plain Rust. Its tests run against the Keycard applet in jCardSim when
//! `KEYCARD_SIMULATOR` names one. The Logos glue is behind `logos_module`.

pub mod accounts;
pub mod answers;
pub mod card;
pub mod link;
pub mod signer;
#[cfg(feature = "simulator")]
pub mod sim;
pub mod store;

#[cfg(feature = "logos_module")]
mod glue;
