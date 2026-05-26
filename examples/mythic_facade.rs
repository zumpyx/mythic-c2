//! Mythic 门面使用示例 — 三种场景，加密由 C2 决定。
//!
//! `Mythic` 只持有 UUID。每次 `build_*` / `parse_*` 时从 C2 读 `aes_psk()`，
//! 有 key 就加密、没有就明文。IV 由 Mythic 内部计数器自动生成。

use mythic::{Aes256HmacCrypto, C2Transport, CheckinInfo, Mythic};
use uuid::Uuid;

// ── C2 实现: 加密配置是 C2 自身的数据 ──

struct HttpC2 {
    key_b64: Option<String>,
    needs_staging: bool,
}
impl HttpC2 {
    fn send(&self, _p: &str) -> Result<String, String> { Ok(String::new()) }
}
impl C2Transport for HttpC2 {
    type Error = String;
    fn aes_psk(&self) -> Option<String> { self.key_b64.clone() }
    fn encrypted_exchange_check(&self) -> bool { self.needs_staging }
    fn checkin(&self, p: &str) -> Result<String, Self::Error> { self.send(p) }
    fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { self.send(p) }
    fn post_response(&self, p: &str) -> Result<String, Self::Error> { self.send(p) }
}

fn main() {
    let agent_uuid = Uuid::parse_str("f0f0f0f0-1111-2222-3333-444444444444").unwrap();
    let mythic = Mythic::new(agent_uuid);

    // ═══════════════════════════════════════════════════════
    // 场景 1: 明文 — C2.aes_psk() = None
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 1: 明文 ═══\n");

    let c2 = HttpC2 { key_b64: None, needs_staging: false };

    let pkt = mythic.build_checkin(
        CheckinInfo {
            os: Some("linux".into()),
            host: Some("web01".into()),
            user: Some("root".into()),
            pid: Some(1337),
            ips: vec!["10.0.0.1".into()],
            ..Default::default()
        },
        &c2,  // ← 每次传 C2, 内部读 aes_psk()
    ).unwrap();
    println!("→ 明文 checkin:\n  {pkt}\n");

    let pkt = mythic.build_get_tasking(5, &c2).unwrap();
    println!("→ 明文 get_tasking:\n  {pkt}\n");

    // ═══════════════════════════════════════════════════════
    // 场景 2: 静态密钥 — C2.aes_psk() = Some(base64key)
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 2: 静态密钥 ═══\n");

    let c2 = HttpC2 {
        key_b64: Some(Aes256HmacCrypto::new([0xAB; 32]).key_b64()),
        needs_staging: false,
    };

    let pkt = mythic.build_checkin(
        CheckinInfo {
            os: Some("windows".into()),
            host: Some("DESKTOP-XYZ".into()),
            user: Some("admin".into()),
            pid: Some(2048),
            domain: Some("CORP".into()),
            ips: vec!["192.168.1.100".into()],
            ..Default::default()
        },
        &c2,  // ← 有 aes_psk(), 自动 AES 加密
    ).unwrap();
    println!("→ 加密 checkin:\n  {pkt}\n");

    let pkt = mythic.build_get_tasking(5, &c2).unwrap();
    println!("→ 加密 get_tasking:\n  {pkt}\n");

    // ═══════════════════════════════════════════════════════
    // 场景 3: RSA 密钥交换 — C2 有 AESPSK, 需要 staging
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 3: RSA 密钥交换 ═══\n");

    let c2 = HttpC2 {
        key_b64: Some(Aes256HmacCrypto::new([0x55; 32]).key_b64()),
        needs_staging: true,
    };

    let pkt = mythic.build_staging_rsa(
        "-----BEGIN PUBLIC KEY-----\nagent-rsa-pub-key\n-----END PUBLIC KEY-----",
        "staging-session-1",
        &c2,  // ← 用 AESPSK 加密
    ).unwrap();
    println!("→ staging_rsa (AESPSK 加密):\n  {pkt}\n");

    // 实际使用时:
    // let reply = c2.staging_rsa(&pkt).unwrap();
    // let (_, resp) = mythic.parse_staging_rsa(&reply, &c2).unwrap();
    // mythic.set_agent_uuid(resp.uuid);
    // // RSA-decrypt session_key, update C2's key_b64 for the new key

    // ═══════════════════════════════════════════════════════
    // 组合 API: 一行 build→send→parse
    // ═══════════════════════════════════════════════════════
    println!("═══ 组合 API (一行版) ═══\n");

    // let (_, resp) = mythic.checkin(info, &c2)?;
    // let (_, tasks) = mythic.get_tasking(5, &c2)?;
    // let (_, ack) = mythic.post_response(results, &c2)?;
    // let (_, stage) = mythic.staging_rsa(pub_key, sid, &c2)?;

    println!("Done.");
}
