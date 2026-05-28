//! Example demonstrating the `#![no_std]` mythic-c2 library — full agent lifecycle.
//!
//! The library crate compiles as `#![no_std]` (`cargo build`).  This example
//! binary links std only for `fn main()` — the API surface shown here uses
//! only `alloc` / `core` types and works identically in a true no_std implant.
//!
//! **Note:** `HttpC2` is a **stub** that returns empty strings.  Running this
//! example will panic at `.unwrap()` because the decode step receives an empty
//! response.  A real transport must return valid base64-encoded Mythic wire
//! packets.  See the unit tests for working encode/decode roundtrips.

use mythic::{Aes256HmacCrypto, C2Transport, MythicAgent, TaskResponse};
use uuid::Uuid;

// ── C2 transport stub ──────────────────────────────────────

/// A fake HTTP transport for demonstration purposes.
/// In a real implant this would make actual HTTP(S) requests.
struct HttpC2 {
    key_b64: Option<String>,
}

impl C2Transport for HttpC2 {
    type Error = String;

    fn aes_psk(&self) -> Option<String> {
        self.key_b64.clone()
    }

    fn random_iv(&self) -> Result<[u8; 16], Self::Error> {
        let iv = [0u8; 16];
        // In a real implant, fill with cryptographically random bytes
        // (e.g. `getrandom::getrandom(&mut iv)` or a platform TRNG).
        // Zero IV is only safe for plaintext transports.
        Ok(iv)
    }

    fn checkin(&self, pkt: &str) -> Result<String, Self::Error> {
        eprintln!("[HTTP] checkin  → {} bytes", pkt.len());
        // Real impl: POST to <server>/agent_message
        Ok(String::new())
    }

    fn get_tasking(&self, pkt: &str) -> Result<String, Self::Error> {
        eprintln!("[HTTP] get_task → {} bytes", pkt.len());
        // Real impl: GET <server>/agent_message with base64 body
        Ok(String::new())
    }

    fn post_response(&self, pkt: &str) -> Result<String, Self::Error> {
        eprintln!("[HTTP] post_resp → {} bytes", pkt.len());
        Ok(String::new())
    }
}

fn main() {
    let payload_uuid = Uuid::parse_str("f0f0f0f0-1111-2222-3333-444444444444").unwrap();

    // ── Plaintext checkin ─────────────────────────────────
    {
        let c2 = HttpC2 { key_b64: None };
        let agent = MythicAgent::new(payload_uuid)
            .checkin(&c2, vec!["10.0.0.1".into()], "linux", "root", "web01", 1337, "x86_64")
            .unwrap();
        println!("Plaintext callback UUID: {}", agent.callback_uuid());
    }

    // ── Static-key checkin ────────────────────────────────
    {
        let key = Aes256HmacCrypto::new([0xAB; 32]).key_b64();
        let c2 = HttpC2 { key_b64: Some(key) };
        let agent = MythicAgent::new(payload_uuid)
            .checkin(&c2, vec!["192.168.1.100".into()], "windows", "admin", "DESKTOP-XYZ", 2048, "x86_64")
            .unwrap();
        println!("Static-key callback UUID: {}", agent.callback_uuid());
    }

    // ── Full lifecycle: get_tasking → post_response ───────
    {
        let c2 = HttpC2 { key_b64: None };

        // 1. Checkin
        let mut agent = MythicAgent::new(payload_uuid)
            .checkin(&c2, vec!["10.0.0.2".into()], "linux", "operator", "implant01", 9999, "aarch64")
            .unwrap();

        // 2. Poll for tasks
        match agent.get_tasking(1, &c2) {
            Ok(resp) => {
                for task in &resp.tasks {
                    println!("Received task {}: {}", task.id, task.command);

                    // 3. Execute and respond
                    let _ = agent.post_response(
                        vec![TaskResponse::completed(task.id, "task executed successfully")],
                        &c2,
                    );
                }
            }
            Err(e) => eprintln!("get_tasking failed: {e}"),
        }
    }

    println!("All demo scenarios complete.");
}
