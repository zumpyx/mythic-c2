//! Serde roundtrip tests for Mythic 4.0 message structures.
//!
//! These tests use `std` for convenience; the library itself remains `no_std`.

use mythic::{
    AgentRpc, Alert, Artifact, CallbackToken, CallbackUpdate, CheckinRequest, CheckinResponse,
    CommandUpdate, Credential, Delegate, Download, Edge, FileBrowserEntry, GetTaskingRequest,
    GetTaskingResponse, InteractiveMessage, Keylog, PostResponseRequest, PostResponseResponse,
    ProcessInfo, ProcessListing, RemovedFile, RpfwdMessage, SocksMessage, Task, TaskResponse,
    TaskResponseAck, Token, Upload,
};
use serde_json::json;

const PAYLOAD_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CALLBACK_UUID: &str = "11111111-2222-3333-4444-555555555555";
const TASK_ID: &str = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb";

fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let json = serde_json::to_vec(value).unwrap();
    serde_json::from_slice(&json).unwrap()
}

fn json_of<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
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
fn checkin_omits_empty_optionals() {
    let req = CheckinRequest::new(PAYLOAD_UUID);
    let v = json_of(&req);
    assert!(v.get("os").is_none());
    assert!(v.get("ips").is_none());
    assert!(v.get("delegates").is_none());
    assert!(v.get("alerts").is_none());
    assert!(v.get("edges").is_none());
}

#[test]
fn checkin_response_roundtrip() {
    let resp = CheckinResponse::success(CALLBACK_UUID);
    let decoded: CheckinResponse = roundtrip(&resp);

    assert!(decoded.is_success());
    assert_eq!(decoded.id, CALLBACK_UUID);
    assert!(!CheckinResponse {
        action: "checkin".into(),
        id: CALLBACK_UUID.into(),
        status: "error".into(),
    }
    .is_success());
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

#[test]
fn task_response_hooking_features() {
    let mut tr = TaskResponse::new(TASK_ID);
    tr.user_output = Some("out".into());
    tr.completed = Some(true);
    tr.status = Some("success".into());
    tr.error = Some("none".into());
    tr.process_response = Some(json!({"ok": true}));
    tr.removed_files = vec![RemovedFile {
        host: "h".into(),
        path: "/tmp/a".into(),
    }];
    tr.artifacts = vec![Artifact {
        base_artifact: "Process Create".into(),
        artifact: "cmd.exe".into(),
        host: Some("h".into()),
    }];
    tr.processes = Some(ProcessListing {
        host: Some("h".into()),
        os: Some("Windows".into()),
        update_deleted: Some(true),
        processes: vec![ProcessInfo {
            process_id: 4,
            parent_process_id: Some(0),
            architecture: Some("x64".into()),
            bin_path: Some("C:\\Windows\\System32\\smss.exe".into()),
            name: "smss.exe".into(),
            user: Some("SYSTEM".into()),
            command_line: None,
            integrity_level: Some(4),
            start_time: None,
            description: None,
            signer: None,
            protected_process_level: None,
            extra: None,
        }],
    });
    tr.commands = vec![CommandUpdate {
        action: "add".into(),
        cmd: "shell".into(),
    }];
    tr.keylogs = vec![Keylog {
        window_title: "notepad".into(),
        user: "bob".into(),
        keystrokes: "hello".into(),
    }];
    tr.tokens = vec![Token {
        token_id: 1,
        host: Some("h".into()),
        user: Some("admin".into()),
        groups: None,
        privileges: None,
        thread_id: None,
        process_id: Some(100),
        session_id: None,
        logon_sid: None,
        integrity_level_sid: None,
        restricted: Some(false),
        default_dacl: None,
        handle: None,
        capabilities: None,
        app_container_sid: None,
        app_container_number: None,
    }];
    tr.callback_tokens = vec![CallbackToken {
        action: "add".into(),
        host: Some("h".into()),
        token_id: 1,
    }];
    tr.download = Some(Download {
        total_size: Some(1024),
        total_chunks: Some(2),
        chunk_size: Some(512),
        host: Some("h".into()),
        is_screenshot: Some(false),
        filename: Some("a.txt".into()),
        full_path: Some("/tmp/a.txt".into()),
        file_id: None,
        chunk_offset: None,
        chunk_num: Some(1),
        chunk_data: Some("AAAA".into()),
    });
    tr.upload = Some(Upload {
        file_id: "file-uuid".into(),
        host: Some("h".into()),
        chunk_size: Some(512),
        chunk_num: Some(1),
        full_path: Some("/tmp/b.txt".into()),
        chunk_data: Some("BBBB".into()),
    });
    tr.agent_rpc = Some(AgentRpc {
        name: "lookup".into(),
        arguments: json!({"key": "host"}),
    });
    tr.callback = Some(CallbackUpdate {
        cwd: Some("/tmp".into()),
        impersonation_context: Some("DOMAIN\\user".into()),
        sleep_info: Some("10s".into()),
        pid: Some(99),
        extra_info: None,
        extra: None,
    });

    let decoded: TaskResponse = roundtrip(&tr);
    assert_eq!(decoded.task_id, TASK_ID);
    assert_eq!(decoded.artifacts.len(), 1);
    assert_eq!(decoded.processes.as_ref().unwrap().processes.len(), 1);
    assert_eq!(decoded.download.as_ref().unwrap().filename.as_deref(), Some("a.txt"));
    assert_eq!(decoded.agent_rpc.as_ref().unwrap().name, "lookup");
    assert_eq!(decoded.callback.as_ref().unwrap().pid, Some(99));
}

#[test]
fn top_level_channels() {
    let req = GetTaskingRequest {
        action: "get_tasking".into(),
        tasking_size: 1,
        get_delegate_tasks: None,
        delegates: vec![Delegate {
            message: "b64".into(),
            c2_profile: "tcp".into(),
            uuid: "child".into(),
            new_uuid: None,
        }],
        responses: vec![],
        socks: vec![SocksMessage {
            server_id: 1,
            data: "AAAA".into(),
            exit: false,
        }],
        rpfwd: vec![RpfwdMessage {
            server_id: 2,
            data: "BBBB".into(),
            exit: true,
        }],
        interactive: vec![InteractiveMessage {
            task_id: TASK_ID.into(),
            message_type: 0,
            data: "CCCC".into(),
        }],
        alerts: vec![Alert {
            alert: "a".into(),
            level: "info".into(),
            source: None,
            send_webhook: None,
            webhook_alert: None,
        }],
        edges: vec![],
    };

    let decoded: GetTaskingRequest = roundtrip(&req);
    assert_eq!(decoded.delegates.len(), 1);
    assert_eq!(decoded.socks.len(), 1);
    assert!(decoded.rpfwd[0].exit);
    assert_eq!(decoded.interactive[0].message_type, 0);
    assert_eq!(decoded.alerts.len(), 1);
}

#[test]
fn post_response_response_and_ack() {
    let resp = PostResponseResponse {
        action: "post_response".into(),
        responses: vec![TaskResponseAck {
            task_id: TASK_ID.into(),
            status: "success".into(),
            error: None,
            file_id: Some("fid".into()),
            output: Some(json!({"value": 1})),
        }],
        delegates: vec![],
        socks: vec![],
        rpfwd: vec![],
        interactive: vec![],
        alerts: vec![],
        edges: vec![],
    };

    let decoded: PostResponseResponse = roundtrip(&resp);
    assert_eq!(decoded.responses[0].file_id.as_deref(), Some("fid"));
    assert_eq!(decoded.responses[0].status, "success");
}

#[test]
fn nested_file_browser() {
    let entry = FileBrowserEntry {
        host: Some("h".into()),
        is_file: false,
        name: "root".into(),
        parent_path: None,
        success: true,
        access_time: None,
        modify_time: None,
        size: None,
        update_deleted: Some(true),
        files: vec![FileBrowserEntry {
            host: None,
            is_file: false,
            name: "dir".into(),
            parent_path: Some("/".into()),
            success: true,
            access_time: None,
            modify_time: None,
            size: None,
            update_deleted: None,
            files: vec![FileBrowserEntry {
                host: None,
                is_file: true,
                name: "f".into(),
                parent_path: Some("/dir".into()),
                success: true,
                access_time: Some(1),
                modify_time: Some(2),
                size: Some(3),
                update_deleted: None,
                files: vec![],
                extra: None,
            }],
            extra: None,
        }],
        extra: None,
    };

    let decoded: FileBrowserEntry = roundtrip(&entry);
    assert_eq!(decoded.files[0].files[0].name, "f");
    assert_eq!(decoded.files[0].files[0].size, Some(3));
}

#[test]
fn get_tasking_all() {
    let req = GetTaskingRequest::all();
    assert_eq!(req.tasking_size, -1);
    assert_eq!(req.action, "get_tasking");
}
