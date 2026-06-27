//! HTTPX transport for the Mythic `httpx` C2 profile.
//!
//! `httpx` is a superset of the `http` profile: it uses the same
//! `HttpConfig` / `HttpTransport` implementation, defaulting to URL-safe
//! base64-encoded messages in the `id` query parameter for GET tasking.

pub use crate::c2::http::{HttpConfig as HttpxConfig, HttpTransport as HttpxTransport};
