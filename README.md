# mythic-c2

Minimal Rust library implementing the **Mythic C2 4.0** agent message structures
and wire format for **plaintext (unencrypted) communication only**.

This rewrite focuses exclusively on:

- Plaintext check-in
- `get_tasking`
- `post_response`
- Optional P2P `delegates`

No encryption, no RSA staging, no transport layer. Designed for agents that
perform their own C2 profile handling and only need correct message structures
and Base64(UUID + JSON) encoding.

## Wire format

```
Base64( UUID(36 ASCII chars) + JSON bytes )
```

- First check-in uses the **payload UUID**.
- Subsequent messages use the **callback UUID** returned by Mythic.
- The JSON body is never encrypted.

## Key design points

- Protocol action strings (`"checkin"`, `"get_tasking"`, `"post_response"`, `"success"`)
  are obfuscated at compile time with `obfstr`.
- Error `Display` implementations only emit descriptive text under
  `debug_assertions`. Release builds report a generic `"error"`.
- Minimal dependencies: `serde`, `serde_json`, `base64`, `uuid`, `obfstr`.
- Release profile is optimized for size and stripping.

## Quick start

```rust
use mythic::{CheckinRequest, encode_plaintext, decode_plaintext, CheckinResponse};

let payload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

let checkin = CheckinRequest::new(payload_uuid)
    .with_os("linux")
    .with_user("root")
    .with_pid(1337);

let packet = encode_plaintext(payload_uuid, &checkin)?;

// ... send packet via your C2 profile, receive reply ...

let (uuid, resp): (String, CheckinResponse) = decode_plaintext(&reply)?;
let callback_uuid = resp.id;
```

See `examples/plaintext_checkin.rs` for a complete round-trip demonstration.

## Building

```bash
# Native
cargo build --release

# Cross-compile with Zig (example)
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

Requires Rust 1.99+ and (for zigbuild) Zig 0.17+.

## License

GPL-3.0-only
