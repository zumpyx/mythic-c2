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

// Mythic holds UUID; crypto is read from C2 at pack time
let mut mythic = Mythic::new(agent_uuid);

// Build a checkin packet — C2's aes_psk() decides encrypt vs plain
let pkt = mythic.build_checkin(CheckinInfo {
    os: Some("linux".into()),
    host: Some("web01".into()),
    user: Some("root".into()),
    pid: Some(1337),
    ips: vec!["10.0.0.1".into()],
    ..Default::default()
}, &c2).unwrap();
// → Base64( UUID + AES256( JSON({ "action": "checkin", ... }) ) )
```

## Three API Levels

**`Mythic` facade** — crypto comes from C2 at call time:
```rust
let mythic = Mythic::new(uuid);
let pkt = mythic.build_checkin(info, &c2)?;     // C2.aes_psk() decides encrypt/plain
let (_, resp) = mythic.parse_checkin(&reply, &c2)?;
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
| Plaintext | `aes_psk = None` | `build_checkin(info, &c2)` — plain |
| Static key | `aes_psk = Some(key)` | `build_checkin(info, &c2)` — AES encrypted |
| RSA EKE | `aes_psk = Some(key)`, `exchange = true` | `staging_rsa(…, &c2)` → checkin |

See [`examples/mythic_facade.rs`](examples/mythic_facade.rs) for the full agent lifecycle.

## License

GPL-3.0-only
