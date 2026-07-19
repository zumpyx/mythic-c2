use crate::{MythicError, MythicResult, base64_decode, base64_encode};

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub fn aes256_packed(
    uuid: impl AsRef<[u8]>,
    aes_psk: &[u8; 32],
    plaintext: impl AsRef<[u8]>,
) -> MythicResult<String> {
    let mut msg: Vec<u8> = uuid.as_ref().to_vec();

    let mut enc = encrypt(aes_psk, plaintext.as_ref())?;
    msg.append(&mut enc);

    let pack = base64_encode(&msg);

    Ok(pack)
}

pub fn aes256_unpack(
    uuid: impl AsRef<[u8]>,
    aes_psk: &[u8; 32],
    enc_text: impl AsRef<[u8]>,
) -> MythicResult<Vec<u8>> {
    let mut msg = base64_decode(enc_text)?;
    if msg.len() < 36 {
        return Err(MythicError::InvalidPacket);
    }
    let msg_enc = msg.split_off(36);
    if !msg.iter().eq(uuid.as_ref()) {
        return Err(MythicError::UuidMismatch);
    }
    decrypt(aes_psk, &msg_enc)
}

/// 加密: 返回 IV(16) + Ciphertext(PKCS#7 填充) + HMAC(32)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> MythicResult<Vec<u8>> {
    // 1. 生成随机 IV
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // 2. AES-256-CBC 加密（cipher crate 自动处理 PKCS#7 填充）
    let ciphertext = Aes256CbcEnc::new_from_slices(key, &iv)
        .map_err(|_| MythicError::Crypto)?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // 3. 计算 HMAC(IV || ciphertext)
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MythicError::Crypto)?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let hmac = mac.finalize().into_bytes();

    // 4. 拼接输出
    let mut out = Vec::with_capacity(16 + ciphertext.len() + 32);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&hmac);
    Ok(out)
}

/// 解密: 输入 IV(16) + Ciphertext + HMAC(32), 返回去除填充后的明文
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> MythicResult<Vec<u8>> {
    // 最小长度: IV(16) + 至少1个密文块(16字节) + HMAC(32)
    if data.len() < 16 + 16 + 32 {
        return Err(MythicError::AesDecrypt);
    }

    let iv = &data[0..16];
    let hmac_start = data.len() - 32;
    let ciphertext = &data[16..hmac_start];
    let received_hmac = &data[hmac_start..];

    // 密文长度必须是 16 的倍数（CBC 要求）
    if !ciphertext.len().is_multiple_of(16) {
        return Err(MythicError::AesDecrypt);
    }

    // 1. HMAC 验证
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MythicError::Crypto)?;
    mac.update(iv);
    mac.update(ciphertext);
    mac.verify_slice(received_hmac)
        .map_err(|_| MythicError::AesDecrypt)?;

    // 2. AES-256-CBC 解密（自动去除 PKCS#7 填充）
    Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|_| MythicError::AesDecrypt)?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| MythicError::AesDecrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_rejects_short_input() {
        let key = [0x42u8; 32];
        assert!(decrypt(&key, &[0u8; 31]).is_err());
    }

    #[test]
    fn decrypt_rejects_non_block_multiple() {
        let key = [0x42u8; 32];
        // IV(16) + 17 bytes ciphertext (not multiple of 16) + HMAC(32)
        let mut data = vec![0u8; 16 + 17 + 32];
        data[16 + 17..].copy_from_slice(&[0xFF; 32]);
        assert!(decrypt(&key, &data).is_err());
    }
}
