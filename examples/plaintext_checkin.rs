//! Minimal plaintext check-in example for Mythic 4.0.
//!
//! This binary uses `std` for convenience; the library itself is `no_std` + `alloc`.
//! UUID prefixing and base64 wrapping are left to the agent.

use mythic::{CheckinRequest, CheckinResponse};

fn main() {
    let payload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    let checkin = CheckinRequest::new(payload_uuid)
        .with_ips(vec!["127.0.0.1".into()])
        .with_os("linux")
        .with_user("root")
        .with_host("test-host")
        .with_pid(1234)
        .with_architecture("x64");

    let body = serde_json::to_vec(&checkin).unwrap();
    println!("checkin body: {}", String::from_utf8_lossy(&body));

    // Agent would then do: base64(payload_uuid + body)

    let resp = CheckinResponse::success("11111111-2222-3333-4444-555555555555");
    assert!(resp.is_success());
    println!("callback uuid: {}", resp.id);
}
