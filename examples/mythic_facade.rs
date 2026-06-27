//! Example demonstrating the mythic-c2 library — full agent lifecycle.
//!
//! This example shows both a hand-written transport stub and the built-in
//! HTTP/HTTPS transport driven by a Mythic payload-builder configuration.

use mythic::{Aes256HmacCrypto, C2Transport, MythicAgent, MythicError, TaskResponse};
use uuid::Uuid;

// ── C2 transport stub ──────────────────────────────────────

/// A fake HTTP transport for demonstration purposes.
struct HttpC2 {
    key_b64: Option<String>,
}

impl C2Transport for HttpC2 {
    fn get_aes_psk(&self) -> Option<String> {
        self.key_b64.clone()
    }

    fn random_iv(&self) -> Result<[u8; 16], MythicError> {
        Ok([0u8; 16])
    }

    fn checkin(&self, pkt: &str) -> Result<String, MythicError> {
        eprintln!("[HTTP] checkin  -> {} bytes", pkt.len());
        Ok(String::new())
    }

    fn get_tasking(&self, pkt: &str) -> Result<String, MythicError> {
        eprintln!("[HTTP] get_task -> {} bytes", pkt.len());
        Ok(String::new())
    }

    fn post_response(&self, pkt: &str) -> Result<String, MythicError> {
        eprintln!("[HTTP] post_resp -> {} bytes", pkt.len());
        Ok(String::new())
    }
}

// ── Built-in transport configuration example ───────────────

#[cfg(any(feature = "http", feature = "httpx"))]
fn demo_config_deserialization() {
    use mythic::C2Profiles;
    use mythic::c2::http::HttpConfig;

    let builder_json = r#"{
        "c2_profiles": [
            {
                "httpx": {
                    "callback_host": "https://example.com",
                    "callback_port": 443,
                    "callback_interval": 10,
                    "callback_jitter": 2,
                    "get_uri": "index",
                    "post_uri": "data",
                    "query_path_name": "id",
                    "encrypted_exchange_check": true
                }
            }
        ]
    }"#;

    let profiles: C2Profiles = serde_json::from_str(builder_json).unwrap();
    for p in profiles {
        println!("profile: {}", p.name());
        if let Ok(_transport) = p.build() {
            println!("transport built successfully");
        }
    }

    // Direct configuration works too.
    let _cfg = HttpConfig {
        callback_host: "https://example.com".into(),
        callback_port: 443,
        get_uri: "index".into(),
        post_uri: "data".into(),
        query_path_name: Some("id".into()),
        ..Default::default()
    };
}

#[cfg(not(any(feature = "http", feature = "httpx")))]
fn demo_config_deserialization() {
    println!("http/httpx feature disabled, skipping config demo");
}

fn main() {
    let payload_uuid = Uuid::parse_str("f0f0f0f0-1111-2222-3333-444444444444").unwrap();

    // ── Configuration deserialization demo ────────────────
    demo_config_deserialization();

    // ── Plaintext checkin ─────────────────────────────────
    {
        let mut c2 = HttpC2 { key_b64: None };
        let agent = MythicAgent::easy_checkin(
            payload_uuid,
            &mut c2,
            vec!["10.0.0.1".into()],
            Some("linux".into()),
            Some("root".into()),
            Some("web01".into()),
            Some(1337),
            Some("x86_64".into()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        println!("Plaintext callback UUID: {}", agent.callback_uuid());
    }

    // ── Static-key checkin ────────────────────────────────
    {
        let key = Aes256HmacCrypto::new([0xAB; 32]).key_b64();
        let mut c2 = HttpC2 { key_b64: Some(key) };
        let agent = MythicAgent::easy_checkin(
            payload_uuid,
            &mut c2,
            vec!["192.168.1.100".into()],
            Some("windows".into()),
            Some("admin".into()),
            Some("DESKTOP-XYZ".into()),
            Some(2048),
            Some("x86_64".into()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        println!("Static-key callback UUID: {}", agent.callback_uuid());
    }

    // ── Full lifecycle: get_tasking -> post_response ──────
    {
        let mut c2 = HttpC2 { key_b64: None };

        let agent = MythicAgent::easy_checkin(
            payload_uuid,
            &mut c2,
            vec!["10.0.0.2".into()],
            Some("linux".into()),
            Some("operator".into()),
            Some("implant01".into()),
            Some(9999),
            Some("aarch64".into()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        match agent.get_tasking(1, &c2) {
            Ok(resp) => {
                for task in &resp.tasks {
                    println!("Received task {}: {}", task.id, task.command);

                    let _ = agent.post_response(
                        vec![TaskResponse::completed(
                            task.id,
                            "task executed successfully",
                        )],
                        &c2,
                    );
                }
            }
            Err(e) => eprintln!("get_tasking failed: {e}"),
        }
    }

    println!("All demo scenarios complete.");
}
