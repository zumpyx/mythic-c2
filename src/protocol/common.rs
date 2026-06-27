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

    let mut enc = encrypt(aes_psk, plaintext.as_ref()).unwrap();
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
        return Err(MythicError::Crypto);
    }

    let iv = &data[0..16];
    let hmac_start = data.len() - 32;
    let ciphertext = &data[16..hmac_start];
    let received_hmac = &data[hmac_start..];

    // 密文长度必须是 16 的倍数（CBC 要求）
    if ciphertext.len() % 16 != 0 {
        return Err(MythicError::Crypto);
    }

    // 1. HMAC 验证
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MythicError::Crypto)?;
    mac.update(iv);
    mac.update(ciphertext);
    mac.verify_slice(received_hmac)
        .map_err(|_| MythicError::Crypto)?;

    // 2. AES-256-CBC 解密（自动去除 PKCS#7 填充）
    Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|_| MythicError::Crypto)?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| MythicError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintexts: &[&[u8]] = &[
            b"",
            b"A",
            b"Hello, world!",
            &[0u8; 16],
            &[0u8; 17],
            &[0u8; 32],
            &[0u8; 47],
        ];

        for pt in plaintexts {
            let enc = encrypt(&key, pt).expect("encrypt");
            let dec = decrypt(&key, &enc).expect("decrypt");
            assert_eq!(
                dec,
                *pt,
                "roundtrip failed for plaintext of length {}",
                pt.len()
            );
        }
    }

    #[test]
    fn tampered_data_is_rejected() {
        let key = [0x99u8; 32];
        let plaintext = b"secret message";
        let mut enc = encrypt(&key, plaintext).unwrap();

        // 篡改密文最后一位（密文部分在 IV 之后、HMAC 之前）
        let last_byte_idx = enc.len() - 33; // 密文最后一个字节的位置
        if last_byte_idx >= 16 {
            enc[last_byte_idx] ^= 1;
        }
        assert!(decrypt(&key, &enc).is_err());

        // 篡改 HMAC
        let mut enc2 = encrypt(&key, plaintext).unwrap();
        let last = enc2.len() - 1;
        enc2[last] ^= 1;
        assert!(decrypt(&key, &enc2).is_err());
    }
}
