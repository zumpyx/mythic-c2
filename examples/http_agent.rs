use mythic::MythicAgent;
use mythic::MythicC2;
use mythic::MythicResult;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    payload_uuid: String,
    c2_profiles: Vec<MythicC2>,
}

fn main() -> MythicResult<()> {
    let (payload_uuid, mut c2_list) = {
        let config: Config = serde_json::from_str(include_str!("../config.json")).unwrap();
        (config.payload_uuid, config.c2_profiles)
    };
    let mut agent = MythicAgent::new(payload_uuid);
    dbg!(&agent);
    dbg!(&c2_list);
    for c2 in &mut c2_list {
        let resp = agent.checkin(
            c2,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        dbg!(resp);
    }
    Ok(())

    // // 2. Main tasking loop
    // loop {
    //     // -1 asks Mythic for all available tasks
    //     let tasks = agent.get_tasking(-1, &c2)?;

    //     for t in &tasks.tasks {
    //         // 3. Execute the task (replace with real work)
    //         let output = format!("completed task {}", t.id);

    //         // 4. Send the response back
    //         agent.post_response(vec![TaskResponse::completed(t.id, &output)], &c2)?;
    //     }

    //     sleep(Duration::from_secs(10));
    // }
}
