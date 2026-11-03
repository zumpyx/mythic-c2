//! Minimal plaintext check-in example for Mythic 4.0.

use mythic::{
    CheckinRequest, CheckinResponse, GetTaskingRequest, PostResponseRequest, TaskResponse,
    decode_plaintext, encode_plaintext,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    // 1. Build and encode check-in
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
    let callback_uuid = decoded.id;
    println!("callback uuid: {}", callback_uuid);

    // 2. Get tasking
    let get = GetTaskingRequest::all();
    let get_encoded = encode_plaintext(&callback_uuid, &get)?;
    println!("get_tasking packet: {}", get_encoded);

    // 3. Post a simple response
    let task_resp = TaskResponse::new("task-uuid-here")
        .with_output("command completed")
        .completed();
    let post = PostResponseRequest::new(vec![task_resp]);
    let post_encoded = encode_plaintext(&callback_uuid, &post)?;
    println!("post_response packet: {}", post_encoded);

    Ok(())
}
