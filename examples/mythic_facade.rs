//! Mythic 门面使用示例 — 三种通信场景 + C2Profile.
//!
//! ## 两层 API
//!
//!   精细控制: build_* / parse_* — 只做编解码, 传输完全由你控制
//!   一行搞定: checkin() / get_tasking() / … — 传入 &impl C2Transport,
//!            内部自动 build → send → parse

use mythic::{Aes256HmacCrypto, C2Transport, CheckinInfo, Mythic};
use uuid::Uuid;

// ── 示例 C2 实现 ───────────────────────────────────────

struct HttpC2;

impl HttpC2 {
    fn send(&self, _packed: &str) -> Result<String, String> {
        // 实际用 ureq/reqwest:
        // ureq::get("https://mythic-server/agent_message")
        //     .query("q", packed).call()?.into_string()
        Ok(String::new()) // 模拟
    }
}

impl C2Transport for HttpC2 {
    type Error = String;

    fn checkin(&self, p: &str) -> Result<String, Self::Error> { self.send(p) }
    fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { self.send(p) }
    fn post_response(&self, p: &str) -> Result<String, Self::Error> { self.send(p) }
    // staging_rsa / staging_translation 有默认实现 → 自动走 checkin
}

fn main() {
    let _c2 = HttpC2;  // 实际使用时传递给 mythic.checkin(info, &_c2)?
    let agent_uuid = Uuid::parse_str("f0f0f0f0-1111-2222-3333-444444444444").unwrap();

    // ═══════════════════════════════════════════════════════
    // 场景 1: 明文传输
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 1: 明文 ═══\n");

    let mythic = Mythic::new(agent_uuid);

    // ── 精细控制: build / send / parse 分步 ──
    let pkt = mythic.build_checkin(CheckinInfo {
        os: Some("linux".into()),
        host: Some("web01".into()),
        user: Some("root".into()),
        pid: Some(1337),
        ips: vec!["10.0.0.1".into()],
        ..Default::default()
    }).unwrap();
    println!("→ checkin 包:\n  {pkt}\n");

    // 实际使用时:
    // let reply = c2.checkin(&pkt).unwrap();
    // let (_uuid, resp) = mythic.parse_checkin(&reply).unwrap();
    // mythic.set_agent_uuid(resp.id);

    let pkt = mythic.build_get_tasking(5).unwrap();
    println!("→ get_tasking 包:\n  {pkt}\n");

    // ═══════════════════════════════════════════════════════
    // 场景 2: 静态密钥
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 2: 静态密钥 ═══\n");

    let crypto = Aes256HmacCrypto::new([0xAB; 32], [0xCD; 16]);
    let mythic = Mythic::with_crypto(agent_uuid, crypto);

    let pkt = mythic.build_checkin(CheckinInfo {
        os: Some("windows".into()),
        host: Some("DESKTOP-XYZ".into()),
        user: Some("admin".into()),
        pid: Some(2048),
        domain: Some("CORP".into()),
        ips: vec!["192.168.1.100".into()],
        ..Default::default()
    }).unwrap();
    println!("→ 加密 checkin:\n  {pkt}\n");
    // let reply = c2.checkin(&pkt).unwrap();
    // let (_uuid, resp) = mythic.parse_checkin(&reply).unwrap();

    // ═══════════════════════════════════════════════════════
    // 场景 3: RSA 密钥交换
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 3: RSA 交换 ═══\n");

    let aes_psk = Aes256HmacCrypto::new([0x55; 32], [0x66; 16]);
    let mythic = Mythic::with_crypto(agent_uuid, aes_psk);

    let pkt = mythic.build_staging_rsa(
        "-----BEGIN PUBLIC KEY-----\nagent-rsa-pub-key\n-----END PUBLIC KEY-----",
        "staging-session-1",
    ).unwrap();
    println!("→ staging_rsa (AESPSK 加密):\n  {pkt}\n");
    // let reply = c2.staging_rsa(&pkt).unwrap();
    // let (_uuid, resp) = mythic.parse_staging_rsa(&reply).unwrap();
    // mythic.set_agent_uuid(resp.uuid);
    // let session_key = rsa_decrypt(priv_key, &resp.session_key);
    // let new_key = Aes256HmacCrypto::new(session_key, iv);
    // mythic.set_crypto(new_key);

    // ═══════════════════════════════════════════════════════
    // 组合 API: 一行搞定 build→send→parse
    // ═══════════════════════════════════════════════════════
    println!("═══ 组合 API (一行版) ═══\n");

    // 等价于上面的 build + c2.checkin + parse 三步, 调用时传 &c2 就行:
    //
    // let (_uuid, resp) = mythic.checkin(info, &c2)?;
    // let (_uuid, tasks) = mythic.get_tasking(5, &c2)?;
    // let (_uuid, ack) = mythic.post_response(results, &c2)?;
    // let (_uuid, staging) = mythic.staging_rsa(pub_key, session_id, &c2)?;
    //
    // build_* / parse_* 继续保留, 需要精细控制时直接用它们.

    println!("Done.");
}
