//! Private set intersection from the Pool OPRF.
//!
//! Two parties each hold a set. The client learns which of *its* elements the
//! server also holds; the server learns nothing about those elements, and not
//! even how many matched. Each side does learn the other's set size - the
//! client the server's (deduplicated), the server the client's (as announced, not deduplicated).
//!
//! See `README.md` for how a run is shaped, what it costs, etc.

pub mod client;
pub mod error;
pub mod protocol;
pub mod server;
pub mod transport;
