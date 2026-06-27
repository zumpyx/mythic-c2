# mythic-c2

Mythic C2 agent protocol library for Rust — message encoding/decoding,
AES-256-CBC-HMAC encryption, RSA encrypted key exchange, and a transport
abstraction layer.

The built-in HTTP/HTTPX transport now uses [`minreq`](https://crates.io/crates/minreq)
with `rustls` only.

## Cargo features

| Feature | Description |
|---|---|
| `httpx` (default) | HTTP/HTTPS with URL-safe base64 query parameters |
| `http` | Plain HTTP/HTTPS transport |
| `rustls` (default) | TLS via `rustls` |
| `rsa-staging` | RSA encrypted key exchange |

`httpx` and `rustls` are enabled by default.

## Quick Start

A complete agent using the built-in `httpx` transport and static AES-256
encryption. The `httpx` and `rustls` features are enabled by default.

```toml
[dependencies]
mythic = "0.2"
uuid = "1"
```

```rust
use std::thread::sleep;
use std::time::Duration;
use mythic::{MythicAgent, TaskResponse};
use mythic::transport::httpx::{HttpxConfig, HttpxTransport};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")?;

    // 32-byte AES-256 key, base64-encoded. Must match the key configured in
    // the Mythic payload builder for this agent.
    let aes_key_b64 = "YOUR_BASE64_AES_256_KEY_HERE";

    // Build the HTTPX transport. Query parameter `id` will carry URL-safe
    // base64 tasking requests, matching the Mythic `httpx` profile.
    let cfg = HttpxConfig {
        callback_host: "https://c2.example.com".into(),
        callback_port: 443,
        get_uri: "index".into(),
        post_uri: "data".into(),
        query_path_name: Some("id".into()),
        aes_psk: Some(aes_key_b64.into()),
        ..Default::default()
    };
    let mut c2 = HttpxTransport::new(cfg)?;

    // 1. Checkin
    let agent = MythicAgent::easy_checkin(
        payload_uuid,
        &mut c2,
        vec!["10.0.0.1".into()],
        Some("linux".into()),
        Some("root".into()),
        Some("web01".into()),
        Some(1337),
        Some("x86_64".into()),
        None, None, None, None, None, None,
    )?;
    println!("callback UUID: {}", agent.callback_uuid());

    // 2. Main tasking loop
    loop {
        // -1 asks Mythic for all available tasks
        let tasks = agent.get_tasking(-1, &c2)?;

        for t in &tasks.tasks {
            // 3. Execute the task (replace with real work)
            let output = format!("completed task {}", t.id);

            // 4. Send the response back
            agent.post_response(
                vec![TaskResponse::completed(t.id, &output)],
                &c2,
            )?;
        }

        sleep(Duration::from_secs(10));
    }
}
```

## Built-in transports

The library can deserialize Mythic payload-builder configurations directly:

```rust
use mythic::C2Profiles;

let builder_json = r#"{
    "c2_profiles": [
        { "httpx": {
            "callback_host": "https://example.com",
            "callback_port": 443,
            "get_uri": "index",
            "post_uri": "data",
            "query_path_name": "id"
        }}
    ]
}"#;

let profiles: C2Profiles = serde_json::from_str(builder_json).unwrap();
for p in profiles {
    let transport = p.build().unwrap();
    // transport.checkin(...), transport.get_tasking(...), ...
}
```

Each transport implements `C2Transport` and can be used directly without the
config enum:

```rust
use mythic::transport::http::{HttpConfig, HttpTransport};

let cfg = HttpConfig {
    callback_host: "https://example.com".into(),
    callback_port: 443,
    get_uri: "index".into(),
    post_uri: "data".into(),
    query_path_name: Some("id".into()),
    ..Default::default()
};
let transport = HttpTransport::new(cfg).unwrap();
```

## Three API Levels

**`MythicAgent` facade** — high-level checkin / get_tasking / post_response:

```rust
let mut c2 = HttpC2 { key_b64: None };
let agent = MythicAgent::easy_checkin(
    uuid, &mut c2, vec!["10.0.0.1".into()], Some("linux".into()), Some("root".into()),
    Some("web01".into()), Some(1337), Some("x64".into()),
    None, None, None, None, None, None)?;
let tasks = agent.get_tasking(1, &c2)?;
agent.post_response(vec![TaskResponse::completed(task_id, "ok")], &c2)?;
```

**Free functions** — full control over every step:

```rust
let crypto = Aes256HmacCrypto::from_base64_key(key_b64)?;
let iv = c2.random_iv()?;
let pkt = encode_message(&req, uuid, &crypto, &iv)?;
let (_, resp) = decode_message::<RespCheckin>(&reply, Some(uuid), &crypto)?;
```

**Raw types** — use `serde_json` directly on any message struct:

```rust
let req = ReqCheckin::new(uuid, ips, os, user, host, pid, arch, ...);
let json = serde_json::to_vec(&req)?;
```

## C2Transport Trait

Implement for any transport. Three methods required; `get_aes_psk`,
`random_iv`, and `encrypted_exchange_check` have sensible defaults:

```rust
use mythic::{C2Transport, MythicError};

// Encrypted transports MUST override random_iv with a CSPRNG.
// fn random_iv(&self) -> Result<[u8; 16], MythicError> { getrandom::getrandom(&mut iv)?; Ok(iv) }

impl C2Transport for HttpTransport {
    fn get_aes_psk(&self) -> Option<String>               { Some("q83v...".into()) }

    fn checkin(&self, pkt: &str)       -> Result<String, MythicError> { ... }
    fn get_tasking(&self, pkt: &str)   -> Result<String, MythicError> { self.checkin(pkt) }
    fn post_response(&self, pkt: &str) -> Result<String, MythicError> { self.checkin(pkt) }
}
```

`get_aes_psk()` and `encrypted_exchange_check()` default to `None` / `false` — override
only when needed.

## Three Communication Scenarios

| Scenario | C2 config | Flow |
|---|---|---|
| Plaintext | `get_aes_psk = None` | `checkin` → `get_tasking` → `post_response` |
| Static key | `get_aes_psk = Some(key)` | AES-256-CBC-HMAC encrypted versions of the above |
| RSA EKE | `get_aes_psk = None`, `encrypted_exchange_check = true` | RSA staging → checkin (requires `rsa-staging` feature) |

See [`examples/httpx_agent.rs`](examples/httpx_agent.rs) for the HTTPX quick-start example,
and [`examples/mythic_facade.rs`](examples/mythic_facade.rs) for the full agent lifecycle.

## Wire Format

```
Base64( UUID(36) + [ IV(16) + ciphertext + HMAC-SHA256(32) ] )
```

- **Plaintext**: the encrypted portion is replaced with the raw JSON bytes.
- **Encrypted**: AES-256-CBC with PKCS7 padding, encrypt-then-MAC with HMAC-SHA256.
- **UUID**: hyphenated UUIDv4 string (36 ASCII characters).

## Feature Status

| Feature | Status |
|---|---|
| Plaintext comms | Complete |
| Static AES-256-CBC-HMAC | Complete |
| RSA staging key exchange | Complete (behind `rsa-staging`) |
| Translation-container staging | Types defined |
| Checkin / get_tasking / post_response | Complete |
| HTTP / HTTPX transport | Complete (minreq + rustls) |
| File download (agent→mythic) | Types defined |
| File upload (mythic→agent) | Types defined |
| P2P / delegate messages | Types defined |
| SOCKS / RPFWD / interactive | Types defined |
| Hooking features (file browser, credentials, keylogs, etc.) | Types defined |

## License

GPL-3.0-only
