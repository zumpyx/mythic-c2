//! Serde roundtrip tests for Mythic 4.0 message structures.
//!
//! These tests use `std` for convenience; the library itself remains `no_std`.

use mythic::{
    Alert, CheckinRequest, CheckinResponse, Credential, Edge, FileBrowserEntry,
    GetTaskingRequest, GetTaskingResponse, PostResponseRequest, Task, TaskResponse,
};

const PAYLOAD_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CALLBACK_UUID: &str = "11111111-2222-3333-4444-555555555555";
const TASK_ID: &str = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb";

fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let json = serde_json::to_vec(value).unwrap();
    serde_json::from_slice(&json).unwrap()
}

#[test]
fn checkin_roundtrip() {
    let req = CheckinRequest::new(PAYLOAD_UUID)
        .with_ips(vec!["192.168.1.10".into(), "10.0.0.5".into()])
        .with_os("linux")
        .with_user("root")
        .with_host("test-host")
        .with_pid(1337)
        .with_architecture("x64")
        .with_domain("workgroup")
        .with_integrity_level(4)
        .with_external_ip("1.2.3.4")
        .with_process_name("agent")
        .with_cwd("/tmp");

    let decoded: CheckinRequest = roundtrip(&req);

    assert_eq!(decoded.action, "checkin");
    assert_eq!(decoded.uuid, PAYLOAD_UUID);
    assert_eq!(decoded.ips, vec!["192.168.1.10", "10.0.0.5"]);
    assert_eq!(decoded.os.as_deref(), Some("linux"));
    assert_eq!(decoded.pid, Some(1337));
    assert_eq!(decoded.integrity_level, Some(4));
}

#[test]
fn checkin_response_roundtrip() {
    let resp = CheckinResponse::success(CALLBACK_UUID);
    let decoded: CheckinResponse = roundtrip(&resp);

    assert!(decoded.is_success());
    assert_eq!(decoded.id, CALLBACK_UUID);
}

#[test]
fn get_tasking_with_features() {
    let fb = FileBrowserEntry {
        host: Some("host".into()),
        is_file: false,
        name: "/".into(),
        parent_path: None,
        success: true,
        access_time: Some(1700000000),
        modify_time: Some(1700000000),
        size: Some(0),
        update_deleted: None,
        files: vec![FileBrowserEntry {
            host: None,
            is_file: true,
            name: "secret.txt".into(),
            parent_path: Some("/tmp".into()),
            success: true,
            access_time: None,
            modify_time: None,
            size: Some(42),
            update_deleted: None,
            files: vec![],
            extra: None,
        }],
        extra: None,
    };

    let mut resp = TaskResponse::new(TASK_ID)
        .with_output("listing done")
        .completed();
    resp.file_browser = Some(fb);
    resp.credentials = vec![Credential {
        credential_type: "plaintext".into(),
        credential_subtype: None,
        realm: Some("workgroup".into()),
        account: Some("admin".into()),
        credential: "password".into(),
        comment: None,
        custom_display: None,
        metadata: None,
        credential_identity: None,
    }];
    resp.alerts = vec![Alert {
        alert: "suspicious".into(),
        level: "warning".into(),
        source: Some("agent".into()),
        send_webhook: Some(true),
        webhook_alert: None,
    }];

    let req = GetTaskingRequest {
        action: "get_tasking".into(),
        tasking_size: -1,
        get_delegate_tasks: Some(true),
        delegates: vec![],
        responses: vec![resp],
        socks: vec![],
        rpfwd: vec![],
        interactive: vec![],
        alerts: vec![],
        edges: vec![Edge {
            source: CALLBACK_UUID.into(),
            destination: "other-uuid".into(),
            action: "add".into(),
            c2_profile: "smb".into(),
            metadata: Some("link".into()),
        }],
    };

    let decoded: GetTaskingRequest = roundtrip(&req);

    assert_eq!(decoded.tasking_size, -1);
    assert_eq!(decoded.responses.len(), 1);
    assert!(decoded.responses[0].completed.unwrap_or(false));
    assert!(decoded.responses[0].file_browser.is_some());
    assert_eq!(decoded.responses[0].credentials.len(), 1);
    assert_eq!(decoded.edges.len(), 1);
}

#[test]
fn post_response_roundtrip() {
    let tr = TaskResponse::new(TASK_ID)
        .with_output("done")
        .completed()
        .with_status("success");

    let req = PostResponseRequest::new(vec![tr]);
    let decoded: PostResponseRequest = roundtrip(&req);

    assert_eq!(decoded.action, "post_response");
    assert_eq!(decoded.responses.len(), 1);
    assert_eq!(decoded.responses[0].status.as_deref(), Some("success"));
}

#[test]
fn get_tasking_response_with_tasks() {
    let resp = GetTaskingResponse {
        action: "get_tasking".into(),
        tasks: vec![Task {
            command: "shell".into(),
            parameters: "whoami".into(),
            timestamp: 1700000000.0,
            id: TASK_ID.into(),
        }],
        delegates: vec![],
        responses: vec![],
        socks: vec![],
        rpfwd: vec![],
        interactive: vec![],
        alerts: vec![],
        edges: vec![],
    };

    let decoded: GetTaskingResponse = roundtrip(&resp);

    assert_eq!(decoded.tasks.len(), 1);
    assert_eq!(decoded.tasks[0].command, "shell");
    assert_eq!(decoded.tasks[0].parameters, "whoami");
}
