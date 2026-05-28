# mythic-c2

Mythic C2 agent protocol library for Rust — message encoding/decoding,
AES-256-CBC-HMAC encryption, and a transport abstraction layer.

`#![no_std]` compatible with `alloc`, suitable for embedded agent binaries.

## Quick Start

```rust
use mythic::{Aes256HmacCrypto, C2Transport, MythicAgent, MythicError, TaskResponse};
use uuid::Uuid;

// Implement C2Transport for your channel (HTTP, DNS, WebSocket, etc.)
struct HttpC2 { key_b64: Option<String> }

impl C2Transport for HttpC2 {
    fn get_aes_psk(&self) -> Option<String>        { self.key_b64.clone() }
    fn checkin(&self, p: &str)       -> Result<String, MythicError> { /* POST ... */ Ok(String::new()) }
    fn get_tasking(&self, p: &str)   -> Result<String, MythicError> { /* GET  ... */ Ok(String::new()) }
    fn post_response(&self, p: &str) -> Result<String, MythicError> { /* POST ... */ Ok(String::new()) }
}

let payload_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
let c2 = HttpC2 { key_b64: None };

// 1. Checkin
let agent = MythicAgent::easy_checkin(
    payload_uuid,
    &c2,
    vec!["10.0.0.1".into()],
    Some("linux".into()), Some("root".into()), Some("web01".into()),
    Some(1337), Some("x86_64".into()),
    None, None, None, None, None, None,
)
.unwrap();

// 2. Poll for tasks
let tasks = agent.get_tasking(1, &c2).unwrap();
for t in &tasks.tasks {
    // 3. Execute and respond
    agent.post_response(
        vec![TaskResponse::completed(t.id, "done")],
        &c2,
    ).unwrap();
}
```

## Three API Levels

**`MythicAgent` facade** — high-level checkin / get_tasking / post_response:

```rust
let agent = MythicAgent::easy_checkin(
    uuid, &c2, vec!["10.0.0.1".into()], Some("linux".into()), Some("root".into()),
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

Implement for any transport (HTTP, DNS, WebSocket, etc.). Three methods
required; `get_aes_psk`, `random_iv`, and `encrypted_exchange_check`
have sensible defaults:

```rust
use mythic::{C2Transport, MythicError};

// 加密 transport 必须覆盖 random_iv 提供真随机 IV
//  fn random_iv(&self) -> Result<[u8; 16], MythicError> { getrandom::getrandom(&mut iv)?; Ok(iv) }

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
| RSA EKE | `get_aes_psk = Some(key)`, `exchange = true` | RSA staging → checkin (types defined, RSA crypto not yet implemented) |

See [`examples/mythic_facade.rs`](examples/mythic_facade.rs) for the full agent lifecycle.

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
| RSA staging key exchange | Types defined, RSA crypto not yet implemented |
| Translation-container staging | Types defined |
| Checkin / get_tasking / post_response | Complete |
| File download (agent→mythic) | Types defined |
| File upload (mythic→agent) | Types defined |
| P2P / delegate messages | Types defined |
| SOCKS / RPFWD / interactive | Types defined |
| Hooking features (file browser, credentials, keylogs, etc.) | Types defined |

## License

GPL-3.0-only
