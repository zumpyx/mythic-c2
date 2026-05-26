//! Mythic 门面使用示例 — C2 自带加密配置, `Mythic::from_c2()` 自动读取.
//!
//! ## 三层 API
//!
//!   from_c2:      Mythic::from_c2(uuid, &c2, iv) — C2 提供 key+staging 标记
//!   精细控制:      build_* / parse_* — 只做编解码, 传输由你控制
//!   组合方法:      checkin() / get_tasking() / … — 传入 &impl C2Transport
//!                 内部自动 build → send → parse

use mythic::{Aes256HmacCrypto, C2Transport, CheckinInfo, Mythic};
use uuid::Uuid;

// ── 示例: C2 自带加密配置, Mythic 从 C2 读取 ──────────

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

    // ═══════════════════════════════════════════════════════
    // 场景 1: 明文 — C2 无 key, 不需要 staging
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 1: 明文 ═══\n");

    let _c2 = HttpC2 { key_b64: None, needs_staging: false };
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
    // 场景 2: 静态密钥 — C2 自带 key, 不需要 staging
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 2: 静态密钥 ═══\n");

    let c2 = HttpC2 {
        key_b64: Some(Aes256HmacCrypto::new([0xAB; 32]).key_b64()),
        needs_staging: false,
    };
    let mythic = Mythic::from_c2(agent_uuid, &c2);  // 从 C2 读 key, IV 自动生成

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
    // 场景 3: RSA 密钥交换 — C2 自带 AESPSK, 需要 staging
    // ═══════════════════════════════════════════════════════
    println!("═══ 场景 3: RSA 密钥交换 ═══\n");

    let c2 = HttpC2 {
        key_b64: Some(Aes256HmacCrypto::new([0x55; 32]).key_b64()),
        needs_staging: true,
    };
    let mythic = Mythic::from_c2(agent_uuid, &c2);

    let pkt = mythic.build_staging_rsa(
        "-----BEGIN PUBLIC KEY-----\nagent-rsa-pub-key\n-----END PUBLIC KEY-----",
        "staging-session-1",
    ).unwrap();
    println!("→ staging_rsa (AESPSK 加密):\n  {pkt}\n");
    // let reply = c2.staging_rsa(&pkt).unwrap();
    // let (_uuid, resp) = mythic.parse_staging_rsa(&reply).unwrap();
    // mythic.set_agent_uuid(resp.uuid);
    // let session_key = rsa_decrypt(priv_key, &resp.session_key);
    // let new_key = Aes256HmacCrypto::new(session_key);
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
