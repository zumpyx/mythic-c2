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

The `wire` module owns only the UUID prefix + base64 wrapping. Body serialization is pure serde.

- First check-in uses the **payload UUID**.
- Subsequent messages use the **callback UUID** returned by Mythic.
- The body is never encrypted.

## Supported messages & features

- Checkin / CheckinResponse
- GetTaskingRequest / GetTaskingResponse
- PostResponseRequest / PostResponseResponse
- Full hooking features inside `TaskResponse`:
  - user_output, completed, status, error, process_response
  - file_browser, removed_files, credentials, artifacts, processes
  - edges, commands, keylogs, tokens, callback_tokens
  - download (offset + chunk modes), upload, alerts, agent_rpc, callback
- Top-level: delegates, socks, rpfwd, interactive

## Key design points

- `#![no_std]` + `extern crate alloc`
- Action strings obfuscated at compile time with `obfstr`
- Error text only under `debug_assertions`
- Optional fields use `skip_serializing_if`
- Open-ended fields use `serde_json::Value`

## Quick start

```rust
use mythic::{CheckinRequest, encode_plaintext, decode_plaintext, CheckinResponse};

let payload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

let checkin = CheckinRequest::new(payload_uuid)
    .with_os("linux")
    .with_user("root")
    .with_pid(1337);

let packet = encode_plaintext(payload_uuid, &checkin)?;

let (uuid, resp): (String, CheckinResponse) = decode_plaintext(&reply)?;
```

## License

GPL-3.0-only
