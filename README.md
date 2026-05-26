# mythic-c2

Mythic C2 agent protocol library for Rust — message encoding/decoding,
AES-256-CBC-HMAC encryption, and a transport abstraction layer.

`#![no_std]` compatible with `alloc`, suitable for embedded agent binaries.

## Quick Start

```rust
use mythic::{Mythic, Aes256HmacCrypto, CheckinInfo};
use uuid::Uuid;

let agent_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
let crypto = Aes256HmacCrypto::new([0xAB; 32], [0xCD; 16]);
let mut mythic = Mythic::with_crypto(agent_uuid, crypto);

// Build a checkin packet — ready to send
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

## Two API Levels

**`Mythic` facade** — holds UUID and crypto, one call per operation:

```rust
let mythic = Mythic::with_crypto(uuid, crypto);
let pkt = mythic.build_checkin(info)?;
let (_, resp) = mythic.parse_checkin(&reply)?;
mythic.set_agent_uuid(resp.id);  // switch to callback UUID
```

**Free functions** — full control over every step:

```rust
let req = ReqCheckin::new(uuid, info);
let pkt = encode_message(&req, uuid, &crypto)?;
let (_, resp) = decode_message::<RespCheckin>(&reply, Some(uuid), &crypto)?;
```

## C2Transport Trait

Implement `C2Transport` for any transport (HTTP, DNS, WebSocket, etc.):

```rust
use mythic::C2Transport;

struct HttpTransport;

impl C2Transport for HttpTransport {
    type Error = Box<dyn std::error::Error>;

    fn checkin(&self, pkt: &str) -> Result<String, Self::Error> {
        ureq::get("https://server/agent_message").query("q", pkt).call()?.into_string().map_err(Into::into)
    }
    fn get_tasking(&self, pkt: &str)       -> Result<String, Self::Error> { self.checkin(pkt) }
    fn post_response(&self, pkt: &str)     -> Result<String, Self::Error> { self.checkin(pkt) }
}
```

Then use combined methods:

```rust
let (uuid, resp) = mythic.checkin(info, &transport)?;
```

## Three Communication Scenarios

| Scenario | Init | Checkin |
|---|---|---|
| Plaintext | `Mythic::new(uuid)` | `build_checkin()` — no encryption |
| Static key | `Mythic::with_crypto(uuid, key)` | `build_checkin()` — AES encrypted |
| RSA EKE | `Mythic::with_crypto(uuid, aes_psk)` → staging → `set_crypto(…)` | `build_checkin()` — negotiated key |

See [`examples/mythic_facade.rs`](examples/mythic_facade.rs) for the full agent lifecycle.

## License

GPL-3.0-only
