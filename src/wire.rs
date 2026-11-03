//! Plaintext wire format.
//!
//! `Base64( UUID(36 ASCII bytes) + body )`
//!
//! - `json` feature: body is JSON
//! - `raw` feature: body is length-prefixed binary (zerocopy header)

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use base64::{engine::general_purpose::STANDARD, Engine};

const UUID_LEN: usize = 36;

fn finish(uuid: &str, body: &[u8]) -> Result<String> {
    if uuid.len() != UUID_LEN {
        return Err(Error::Uuid);
    }
    let mut raw = Vec::with_capacity(UUID_LEN + body.len());
    raw.extend_from_slice(uuid.as_bytes());
    raw.extend_from_slice(body);
    Ok(STANDARD.encode(&raw))
}

fn split(b64: &str) -> Result<(String, Vec<u8>)> {
    let raw = STANDARD.decode(b64).map_err(|_| Error::Base64)?;
    if raw.len() < UUID_LEN {
        return Err(Error::InvalidFormat);
    }
    let uuid = String::from_utf8(raw[..UUID_LEN].to_vec()).map_err(|_| Error::Utf8)?;
    Ok((uuid, raw[UUID_LEN..].to_vec()))
}

// ---------------------------------------------------------------------------
// JSON backend
// ---------------------------------------------------------------------------

#[cfg(feature = "json")]
mod json {
    use super::*;
    use serde::{de::DeserializeOwned, Serialize};

    pub fn encode<T: Serialize>(uuid: &str, msg: &T) -> Result<String> {
        let body = serde_json::to_vec(msg).map_err(|_| Error::Json)?;
        finish(uuid, &body)
    }

    pub fn decode<T: DeserializeOwned>(b64: &str) -> Result<(String, T)> {
        let (uuid, body) = split(b64)?;
        let msg = serde_json::from_slice(&body).map_err(|_| Error::Json)?;
        Ok((uuid, msg))
    }
}

#[cfg(feature = "json")]
pub fn encode_plaintext<T: serde::Serialize>(uuid: &str, msg: &T) -> Result<String> {
    json::encode(uuid, msg)
}

#[cfg(feature = "json")]
pub fn decode_plaintext<T: serde::de::DeserializeOwned>(b64: &str) -> Result<(String, T)> {
    json::decode(b64)
}

// ---------------------------------------------------------------------------
// Raw backend (zerocopy header + length-prefixed fields)
// ---------------------------------------------------------------------------

#[cfg(feature = "raw")]
mod raw {
    use super::*;
    use crate::types::*;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Debug)]
    #[repr(C)]
    struct RawHeader {
        action_tag: u8,
        flags: u8,
        _pad: [u8; 2],
    }

    const TAG_CHECKIN: u8 = 1;
    const TAG_GET_TASKING: u8 = 2;
    const TAG_POST_RESPONSE: u8 = 3;

    pub fn encode_checkin(uuid: &str, msg: &CheckinRequest) -> Result<String> {
        let mut body = Vec::new();
        write_header(&mut body, TAG_CHECKIN);
        write_str(&mut body, &msg.action);
        write_str(&mut body, &msg.uuid);
        write_string_vec(&mut body, &msg.ips);
        write_opt_str(&mut body, msg.os.as_deref());
        write_opt_str(&mut body, msg.user.as_deref());
        write_opt_str(&mut body, msg.host.as_deref());
        write_opt_u32(&mut body, msg.pid);
        write_opt_str(&mut body, msg.architecture.as_deref());
        write_opt_str(&mut body, msg.domain.as_deref());
        write_opt_u32(&mut body, msg.integrity_level);
        write_opt_str(&mut body, msg.external_ip.as_deref());
        write_opt_str(&mut body, msg.encryption_key.as_deref());
        write_opt_str(&mut body, msg.decryption_key.as_deref());
        write_opt_str(&mut body, msg.process_name.as_deref());
        write_delegates(&mut body, &msg.delegates);
        finish(uuid, &body)
    }

    pub fn decode_checkin(b64: &str) -> Result<(String, CheckinRequest)> {
        let (uuid, body) = split(b64)?;
        let mut rest = body.as_slice();
        let _ = read_header(&mut rest)?;
        let action = read_str(&mut rest)?;
        let id = read_str(&mut rest)?;
        let ips = read_string_vec(&mut rest)?;
        let os = read_opt_str(&mut rest)?;
        let user = read_opt_str(&mut rest)?;
        let host = read_opt_str(&mut rest)?;
        let pid = read_opt_u32(&mut rest)?;
        let architecture = read_opt_str(&mut rest)?;
        let domain = read_opt_str(&mut rest)?;
        let integrity_level = read_opt_u32(&mut rest)?;
        let external_ip = read_opt_str(&mut rest)?;
        let encryption_key = read_opt_str(&mut rest)?;
        let decryption_key = read_opt_str(&mut rest)?;
        let process_name = read_opt_str(&mut rest)?;
        let delegates = read_delegates(&mut rest)?;
        Ok((
            uuid,
            CheckinRequest {
                action,
                uuid: id,
                ips,
                os,
                user,
                host,
                pid,
                architecture,
                domain,
                integrity_level,
                external_ip,
                encryption_key,
                decryption_key,
                process_name,
                delegates,
            },
        ))
    }

    pub fn encode_checkin_resp(uuid: &str, msg: &CheckinResponse) -> Result<String> {
        let mut body = Vec::new();
        write_header(&mut body, TAG_CHECKIN);
        write_str(&mut body, &msg.action);
        write_str(&mut body, &msg.id);
        write_str(&mut body, &msg.status);
        finish(uuid, &body)
    }

    pub fn decode_checkin_resp(b64: &str) -> Result<(String, CheckinResponse)> {
        let (uuid, body) = split(b64)?;
        let mut rest = body.as_slice();
        let _ = read_header(&mut rest)?;
        let action = read_str(&mut rest)?;
        let id = read_str(&mut rest)?;
        let status = read_str(&mut rest)?;
        Ok((uuid, CheckinResponse { action, id, status }))
    }

    pub fn encode_get_tasking(uuid: &str, msg: &GetTaskingRequest) -> Result<String> {
        let mut body = Vec::new();
        write_header(&mut body, TAG_GET_TASKING);
        write_str(&mut body, &msg.action);
        body.extend_from_slice(&msg.tasking_size.to_le_bytes());
        write_opt_bool(&mut body, msg.get_delegate_tasks);
        write_delegates(&mut body, &msg.delegates);
        write_task_responses(&mut body, &msg.responses);
        finish(uuid, &body)
    }

    pub fn decode_get_tasking(b64: &str) -> Result<(String, GetTaskingRequest)> {
        let (uuid, body) = split(b64)?;
        let mut rest = body.as_slice();
        let _ = read_header(&mut rest)?;
        let action = read_str(&mut rest)?;
        let tasking_size = read_i32(&mut rest)?;
        let get_delegate_tasks = read_opt_bool(&mut rest)?;
        let delegates = read_delegates(&mut rest)?;
        let responses = read_task_responses(&mut rest)?;
        Ok((
            uuid,
            GetTaskingRequest {
                action,
                tasking_size,
                get_delegate_tasks,
                delegates,
                responses,
            },
        ))
    }

    pub fn encode_post_response(uuid: &str, msg: &PostResponseRequest) -> Result<String> {
        let mut body = Vec::new();
        write_header(&mut body, TAG_POST_RESPONSE);
        write_str(&mut body, &msg.action);
        write_task_responses(&mut body, &msg.responses);
        write_delegates(&mut body, &msg.delegates);
        finish(uuid, &body)
    }

    pub fn decode_post_response(b64: &str) -> Result<(String, PostResponseRequest)> {
        let (uuid, body) = split(b64)?;
        let mut rest = body.as_slice();
        let _ = read_header(&mut rest)?;
        let action = read_str(&mut rest)?;
        let responses = read_task_responses(&mut rest)?;
        let delegates = read_delegates(&mut rest)?;
        Ok((
            uuid,
            PostResponseRequest {
                action,
                responses,
                delegates,
            },
        ))
    }

    // ---- low-level helpers ----

    fn write_header(buf: &mut Vec<u8>, tag: u8) {
        let h = RawHeader {
            action_tag: tag,
            flags: 0,
            _pad: [0; 2],
        };
        buf.extend_from_slice(h.as_bytes());
    }

    fn read_header(data: &mut &[u8]) -> Result<RawHeader> {
        if data.len() < 4 {
            return Err(Error::Raw);
        }
        let (h, rest) = RawHeader::read_from_prefix(*data).map_err(|_| Error::Raw)?;
        *data = rest;
        Ok(h)
    }

    fn write_str(buf: &mut Vec<u8>, s: &str) {
        let len = s.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    fn read_str(data: &mut &[u8]) -> Result<String> {
        if data.len() < 4 {
            return Err(Error::Raw);
        }
        let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        *data = &data[4..];
        if data.len() < len {
            return Err(Error::Raw);
        }
        let s = core::str::from_utf8(&data[..len])
            .map_err(|_| Error::Utf8)?
            .into();
        *data = &data[len..];
        Ok(s)
    }

    fn write_opt_str(buf: &mut Vec<u8>, s: Option<&str>) {
        match s {
            Some(v) => {
                buf.push(1);
                write_str(buf, v);
            }
            None => buf.push(0),
        }
    }

    fn read_opt_str(data: &mut &[u8]) -> Result<Option<String>> {
        if data.is_empty() {
            return Err(Error::Raw);
        }
        let flag = data[0];
        *data = &data[1..];
        if flag == 0 {
            Ok(None)
        } else {
            Ok(Some(read_str(data)?))
        }
    }

    fn write_opt_u32(buf: &mut Vec<u8>, v: Option<u32>) {
        match v {
            Some(n) => {
                buf.push(1);
                buf.extend_from_slice(&n.to_le_bytes());
            }
            None => buf.push(0),
        }
    }

    fn read_opt_u32(data: &mut &[u8]) -> Result<Option<u32>> {
        if data.is_empty() {
            return Err(Error::Raw);
        }
        let flag = data[0];
        *data = &data[1..];
        if flag == 0 {
            Ok(None)
        } else {
            if data.len() < 4 {
                return Err(Error::Raw);
            }
            let n = u32::from_le_bytes(data[..4].try_into().unwrap());
            *data = &data[4..];
            Ok(Some(n))
        }
    }

    fn write_opt_bool(buf: &mut Vec<u8>, v: Option<bool>) {
        match v {
            Some(b) => {
                buf.push(1);
                buf.push(if b { 1 } else { 0 });
            }
            None => buf.push(0),
        }
    }

    fn read_opt_bool(data: &mut &[u8]) -> Result<Option<bool>> {
        if data.is_empty() {
            return Err(Error::Raw);
        }
        let flag = data[0];
        *data = &data[1..];
        if flag == 0 {
            Ok(None)
        } else {
            if data.is_empty() {
                return Err(Error::Raw);
            }
            let b = data[0] != 0;
            *data = &data[1..];
            Ok(Some(b))
        }
    }

    fn write_string_vec(buf: &mut Vec<u8>, v: &[String]) {
        let len = v.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        for s in v {
            write_str(buf, s);
        }
    }

    fn read_string_vec(data: &mut &[u8]) -> Result<Vec<String>> {
        if data.len() < 4 {
            return Err(Error::Raw);
        }
        let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        *data = &data[4..];
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(read_str(data)?);
        }
        Ok(out)
    }

    fn write_delegates(buf: &mut Vec<u8>, v: &[Delegate]) {
        let len = v.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        for d in v {
            write_str(buf, &d.message);
            write_str(buf, &d.c2_profile);
            write_str(buf, &d.uuid);
            write_opt_str(buf, d.new_uuid.as_deref());
        }
    }

    fn read_delegates(data: &mut &[u8]) -> Result<Vec<Delegate>> {
        if data.len() < 4 {
            return Err(Error::Raw);
        }
        let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        *data = &data[4..];
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(Delegate {
                message: read_str(data)?,
                c2_profile: read_str(data)?,
                uuid: read_str(data)?,
                new_uuid: read_opt_str(data)?,
            });
        }
        Ok(out)
    }

    fn write_task_responses(buf: &mut Vec<u8>, v: &[TaskResponse]) {
        let len = v.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        for r in v {
            write_str(buf, &r.task_id);
            write_opt_str(buf, r.user_output.as_deref());
            write_opt_bool(buf, r.completed);
            write_opt_str(buf, r.status.as_deref());
            write_opt_str(buf, r.error.as_deref());
        }
    }

    fn read_task_responses(data: &mut &[u8]) -> Result<Vec<TaskResponse>> {
        if data.len() < 4 {
            return Err(Error::Raw);
        }
        let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        *data = &data[4..];
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(TaskResponse {
                task_id: read_str(data)?,
                user_output: read_opt_str(data)?,
                completed: read_opt_bool(data)?,
                status: read_opt_str(data)?,
                error: read_opt_str(data)?,
            });
        }
        Ok(out)
    }

    fn read_i32(data: &mut &[u8]) -> Result<i32> {
        if data.len() < 4 {
            return Err(Error::Raw);
        }
        let n = i32::from_le_bytes(data[..4].try_into().unwrap());
        *data = &data[4..];
        Ok(n)
    }
}

// Public typed entry points for the raw feature.
// When both features are enabled, the JSON generic functions are preferred
// for the common encode/decode names; raw users call the typed functions.

#[cfg(feature = "raw")]
pub use raw::{
    decode_checkin as raw_decode_checkin, decode_checkin_resp as raw_decode_checkin_resp,
    decode_get_tasking as raw_decode_get_tasking, decode_post_response as raw_decode_post_response,
    encode_checkin as raw_encode_checkin, encode_checkin_resp as raw_encode_checkin_resp,
    encode_get_tasking as raw_encode_get_tasking, encode_post_response as raw_encode_post_response,
};
