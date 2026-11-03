# mythic-c2

Minimal **`no_std` + `alloc`** Rust library implementing the **Mythic C2 4.0** agent message structures and wire format for **plaintext (unencrypted) communication only**.

Pure protocol library — no `std` dependency. Suitable for freestanding agents.

## Usage

```toml
mythic-c2 = "0.3"
```

## Wire format

```
Base64( UUID(36 ASCII chars) + JSON body )
```

- First check-in uses the **payload UUID**.
- Subsequent messages use the **callback UUID**.
- Body is never encrypted.
- `encode_plaintext_urlsafe` for query-parameter C2 profiles.
- `decode_plaintext` accepts both standard and URL-safe base64.

## Supported messages

- Checkin / CheckinResponse
- GetTaskingRequest / GetTaskingResponse
- PostResponseRequest / PostResponseResponse

Hooking features inside `TaskResponse` and/or at top level:

`user_output`, `completed`, `status`, `error`, `process_response`,
`file_browser`, `removed_files`, `credentials`, `artifacts`, `processes`,
`edges`, `commands`, `keylogs`, `tokens`, `callback_tokens`,
`download`, `upload`, `alerts`, `agent_rpc`, `callback`,
`delegates`, `socks`, `rpfwd`, `interactive`

## Design notes

- `#![no_std]` + `alloc`
- Action strings obfuscated at compile time (`obfstr`)
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
