//! Minimal plaintext check-in example for Mythic 4.0.
//!
//! This binary uses `std` for convenience; the library itself is `no_std` + `alloc`.

use mythic::{CheckinRequest, CheckinResponse, decode_plaintext, encode_plaintext};

fn main() -> Result<(), mythic::Error> {
    let payload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    let checkin = CheckinRequest::new(payload_uuid)
        .with_ips(vec!["127.0.0.1".into()])
        .with_os("linux")
        .with_user("root")
        .with_host("test-host")
        .with_pid(1234)
        .with_architecture("x64");

    let encoded = encode_plaintext(payload_uuid, &checkin)?;
    println!("checkin packet: {}", encoded);

    // Simulate server response
    let resp = CheckinResponse::success("11111111-2222-3333-4444-555555555555");
    let resp_encoded = encode_plaintext(payload_uuid, &resp)?;
    let (outer, decoded): (String, CheckinResponse) = decode_plaintext(&resp_encoded)?;
    assert_eq!(outer, payload_uuid);
    assert!(decoded.is_success());
    println!("callback uuid: {}", decoded.id);

    Ok(())
}
