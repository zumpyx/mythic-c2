# mythic-c2

Minimal **`no_std` + `alloc`** Rust library implementing the **Mythic C2 4.0** agent message structures and wire format for **plaintext (unencrypted) communication only**.

This is a pure protocol library. It has no dependency on `std` and is suitable for freestanding agent environments that only need correct message structures and encoding.

## Features

| Feature | Description |
|---------|-------------|
| `json` (default) | `serde` + `serde_json` (alloc) |

```toml
mythic-c2 = "0.3"
```

## Wire format

```
Base64( UUID(36 ASCII chars) + JSON body )
```

- First check-in uses the **payload UUID**.
- Subsequent messages use the **callback UUID** returned by Mythic.
- The body is never encrypted.

## Key design points

- `#![no_std]` + `extern crate alloc`. No `std` dependency.
- Protocol action strings (`"checkin"`, `"get_tasking"`, `"post_response"`, `"success"`) are obfuscated at compile time with `obfstr`.
- Error `Display` implementations only emit descriptive text under `debug_assertions`. Release builds report a generic `"error"`.
- Minimal dependencies: `base64`, `obfstr`, `serde` / `serde_json`.
- Optional fields are skipped when empty via `skip_serializing_if`.

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

## Building

```bash
cargo build --release

# Cross-compile with Zig (example)
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

Requires Rust 1.99+ and (for zigbuild) Zig 0.17+.

## License

GPL-3.0-only
