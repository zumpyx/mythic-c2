# mythic-c2

Minimal **`no_std` + `alloc`** Rust library implementing the **Mythic C2 4.0** agent message structures for **plaintext (unencrypted) communication**.

Pure protocol library — no `std` dependency. Suitable for freestanding agents.

## Usage

```toml
mythic-c2 = "0.4"
```

## Scope

The library provides the message types only. UUID prefixing and base64 wrapping are the agent's responsibility:

```
agent: Base64( UUID(36) + JSON(message) )
```

- First check-in uses the **payload UUID**.
- Subsequent messages use the **callback UUID**.
- Body is never encrypted by this library.

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
use mythic::CheckinRequest;

let payload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

let checkin = CheckinRequest::new(payload_uuid)
    .with_os("linux")
    .with_user("root")
    .with_pid(1337);

let body = serde_json::to_vec(&checkin)?;
// agent then does: base64(payload_uuid + body)
```

## License

GPL-3.0-only
