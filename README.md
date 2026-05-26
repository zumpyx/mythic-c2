# mythic-c2

Mythic C2 agent protocol library for Rust — message encoding/decoding,
AES-256-CBC-HMAC encryption, and a transport abstraction layer.

`#![no_std]` compatible with `alloc`, suitable for embedded agent binaries.

## Quick Start

```rust
use mythic::{Mythic, Aes256HmacCrypto, C2Transport, CheckinInfo};
use uuid::Uuid;

// C2 carries its own crypto config — base64 key + staging flag
struct MyC2 { key_b64: Option<String>, needs_staging: bool }
impl C2Transport for MyC2 {
    type Error = String;
    fn aes_psk(&self) -> Option<String> { self.key_b64.clone() }
    fn encrypted_exchange_check(&self) -> bool { self.needs_staging }
    fn checkin(&self, p: &str) -> Result<String, Self::Error> { /* send p to server */ Ok(String::new()) }
    fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { self.checkin(p) }
    fn post_response(&self, p: &str) -> Result<String, Self::Error> { self.checkin(p) }
}

let agent_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
let c2 = MyC2 { key_b64: Some("q83v...base64key...".into()), needs_staging: false };

// Mythic auto-reads key from C2; IV is generated per message
let mut mythic = Mythic::from_c2(agent_uuid, &c2);

// Build a checkin packet — automatically AES-encrypted
let pkt = mythic.build_checkin(CheckinInfo {
    os: Some("linux".into()),
    host: Some("web01".into()),
    user: Some("root".into()),
    pid: Some(1337),
    ips: vec!["10.0.0.1".into()],
    ..Default::default()
}).unwrap();
// → Base64( UUID + AES256( JSON({ "action": "checkin", ... }) ) )
```

## Three API Levels

**`from_c2`** — C2 carries key + staging flag, Mythic auto-configures:
```rust
let mythic = Mythic::from_c2(uuid, &c2);
```

**`Mythic` facade** — manual control over crypto:
```rust
let mythic = Mythic::new(uuid);                    // plaintext
let mythic = Mythic::with_crypto(uuid, crypto);     // encrypted
let pkt = mythic.build_checkin(info)?;
let (_, resp) = mythic.parse_checkin(&reply)?;
mythic.set_agent_uuid(resp.id);
```

**Free functions** — full control over every step:
```rust
let req = ReqCheckin::new(uuid, info);
let pkt = encode_message(&req, uuid, &crypto)?;
let (_, resp) = decode_message::<RespCheckin>(&reply, Some(uuid), &crypto)?;
```

## C2Transport Trait

Implement for any transport (HTTP, DNS, WebSocket, etc.). Three core methods
required; staging methods and crypto attributes have sensible defaults:

```rust
use mythic::C2Transport;

impl C2Transport for HttpTransport {
    type Error = Box<dyn std::error::Error>;

    // ── Crypto attributes (optional, both default to None/false) ──
    fn aes_psk(&self) -> Option<String> { Some("q83v...".into()) }
    fn encrypted_exchange_check(&self) -> bool { false }

    // ── Core methods (required) ──
    fn checkin(&self, p: &str) -> Result<String, Self::Error> { ... }
    fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { self.checkin(p) }
    fn post_response(&self, p: &str) -> Result<String, Self::Error> { self.checkin(p) }
    // staging_rsa / staging_translation default to checkin
}
```

## Three Communication Scenarios

| Scenario | C2 config | Mythic setup |
|---|---|---|
| Plaintext | `aes_psk = None, exchange = false` | `Mythic::new(uuid)` or `Mythic::from_c2(uuid, &c2)` |
| Static key | `aes_psk = Some(key), exchange = false` | `Mythic::with_crypto(uuid, key)` or `Mythic::from_c2(uuid, &c2)` |
| RSA EKE | `aes_psk = Some(key), exchange = true` | `Mythic::with_crypto(uuid, aes_psk)` → staging → `set_crypto(…)` |

See [`examples/mythic_facade.rs`](examples/mythic_facade.rs) for the full agent lifecycle.

## License

GPL-3.0-only
