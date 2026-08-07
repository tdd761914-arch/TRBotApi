//! Reference HTTP edge and sharded bot registry for TRBotApi.
//!
//! The registry is intentionally independent from a particular MTProto I/O
//! runtime.  Production deployments can implement [`BotTransport`] with an
//! epoll/io_uring reactor and keep this HTTP/core layer unchanged.  The
//! included blocking listener is a small smoke server, not a claim that one
//! process can hold millions of open sockets.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use trbotapi_core::{
    BotRequest, Error, ErrorKind, MAX_JSON_BYTES, MAX_RESPONSE_BYTES, Result, input_peer_for_chat,
    parse_request, write_error, write_ok_bool, write_ok_raw, write_ok_user, write_send_message,
};

mod mtproto;
pub use mtproto::TestDcTransport;

/// Maximum HTTP request held by one worker.
pub const MAX_HTTP_REQUEST_BYTES: usize = 128 * 1024;
const MAX_UPDATES_PER_BOT: usize = 1024;
static REQUEST_ID: AtomicI64 = AtomicI64::new(1);

/// A transport bridge from a Bot API method's TL bytes to an MTProto session.
///
/// The method body is already serialized by `trbotapi-core`.  The transport
/// writes a JSON result object (without the outer `ok` envelope) into `output`.
/// This keeps socket scheduling, auth-key storage and response decoding out of
/// the HTTP worker and lets a high-scale deployment use its own reactor.
pub trait BotTransport: Send {
    /// Sends one boxed MTProto method and writes a Bot API result object.
    fn call(&mut self, method: &[u8], output: &mut [u8]) -> Result<usize>;

    /// Handles any method from the Bot API catalogue with its original JSON
    /// object.  Implementations can map the borrowed fields directly into a
    /// schema writer; no JSON AST or owned request copy is required.  The
    /// default keeps older transports source-compatible while they migrate.
    fn call_bot_api(&mut self, _method: &str, _body: &[u8], _output: &mut [u8]) -> Result<usize> {
        Err(Error::new(ErrorKind::Unsupported, 0, 0))
    }
}

/// Minimal bot identity retained by the edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BotInfo {
    /// Telegram bot user identifier.
    pub id: i64,
    /// First name returned by `getMe`.
    pub first_name: String,
    /// Optional username without `@`.
    pub username: Option<String>,
}

/// A registered bot entry.  The token itself is the map key and is never
/// printed by the server.
pub struct BotEntry {
    /// Public bot profile used by the local `getMe` fast path.
    pub info: BotInfo,
    /// Optional username/access-hash cache for resolving Bot API chat IDs.
    peers: HashMap<i64, i64>,
    /// Webhook URL owned by this gateway, if configured.
    webhook_url: Option<String>,
    /// Bounded JSON update queue.  Update production is transport-owned.
    updates: VecDeque<Vec<u8>>,
    /// Optional MTProto transport supplied by the embedding application.
    transport: Option<Box<dyn BotTransport>>,
}

impl BotEntry {
    /// Creates an entry that can answer `getMe` without a network round trip.
    pub fn new(info: BotInfo) -> Self {
        Self {
            info,
            peers: HashMap::new(),
            webhook_url: None,
            updates: VecDeque::new(),
            transport: None,
        }
    }

    /// Installs an MTProto transport for this bot.
    pub fn with_transport(mut self, transport: Box<dyn BotTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Caches a Telegram access hash learned from an update or resolver.
    pub fn cache_peer(&mut self, chat_id: i64, access_hash: i64) {
        self.peers.insert(chat_id, access_hash);
    }

    /// Adds a pre-rendered Bot API update to the bounded queue.
    pub fn push_update(&mut self, update_json: Vec<u8>) {
        if self.updates.len() >= MAX_UPDATES_PER_BOT {
            self.updates.pop_front();
        }
        self.updates.push_back(update_json);
    }
}

/// Concurrent bot registry.  The map lock is held only for lookup/registration;
/// each bot has its own mutex, so unrelated bots do not serialize requests.
#[derive(Default)]
pub struct BotRegistry {
    bots: RwLock<HashMap<String, Arc<Mutex<BotEntry>>>>,
}

impl BotRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces one bot token without logging it.
    pub fn register(&self, token: String, entry: BotEntry) {
        let mut bots = self.bots.write().expect("registry poisoned");
        bots.insert(token, Arc::new(Mutex::new(entry)));
    }

    fn get(&self, token: &str) -> Option<Arc<Mutex<BotEntry>>> {
        self.bots
            .read()
            .expect("registry poisoned")
            .get(token)
            .cloned()
    }

    /// Number of registered bot sessions, useful for diagnostics.
    pub fn len(&self) -> usize {
        self.bots.read().expect("registry poisoned").len()
    }

    /// Returns true when no bot token is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// HTTP listener configuration.
#[derive(Clone, Debug)]
pub struct HttpConfig {
    /// Address to bind.
    pub bind: SocketAddr,
    /// Number of blocking worker threads in the reference edge.
    pub workers: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            workers: thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(2)
                .max(2),
        }
    }
}

/// Blocking reference HTTP server.  It uses a bounded accept queue and fixed
/// request buffers; replace only this edge with an evented listener for very
/// large connection counts.
pub struct HttpServer {
    config: HttpConfig,
    registry: Arc<BotRegistry>,
}

impl HttpServer {
    /// Creates a server over a shared bot registry.
    pub fn new(config: HttpConfig, registry: Arc<BotRegistry>) -> Self {
        Self { config, registry }
    }

    /// Runs until the listener fails.  Workers are detached and stop with the
    /// process; a supervisor should restart the process after an error.
    pub fn run(self) -> io::Result<()> {
        let listener = TcpListener::bind(self.config.bind)?;
        let queue_capacity = self.config.workers.saturating_mul(32).max(32);
        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..self.config.workers.max(1) {
            let receiver = Arc::clone(&receiver);
            let registry = Arc::clone(&self.registry);
            thread::Builder::new()
                .name(format!("trbot-http-{index}"))
                .spawn(move || {
                    loop {
                        let stream = match receiver.lock().expect("worker queue poisoned").recv() {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };
                        let _ = handle_connection(stream, &registry);
                    }
                })?;
        }

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if sender.send(stream).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

/// Dispatches one already-routed Bot API request into a caller-owned output
/// buffer.  This function is useful with a non-HTTP event loop as well.
pub fn dispatch(
    registry: &BotRegistry,
    token: &str,
    method: &str,
    body: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let entry = registry
        .get(token)
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, 0, 0))?;
    let request = parse_request(method, body)?;
    let mut entry = entry.lock().expect("bot entry poisoned");
    match request {
        BotRequest::Generic { method, body } => {
            let transport = entry
                .transport
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::InvalidState, 0, 0))?;
            let mut result = [0u8; MAX_RESPONSE_BYTES];
            let result_length = transport.call_bot_api(method, body, &mut result)?;
            write_ok_raw(output, &result[..result_length])
        }
        BotRequest::GetMe => {
            let mut tl = [0u8; 64];
            let _ = trbotapi_core::write_get_me(&mut tl)?;
            write_ok_user(
                output,
                entry.info.id,
                true,
                &entry.info.first_name,
                entry.info.username.as_deref(),
            )
        }
        BotRequest::SendMessage {
            chat_id,
            text,
            message_thread_id: _,
            disable_notification,
            protect_content,
            reply_to_message_id,
        } => {
            let peer = input_peer_for_chat(
                chat_id,
                Some(entry.info.id),
                entry.peers.get(&chat_id).copied(),
            )?;
            let random_id = next_random_id();
            let mut tl = [0u8; MAX_JSON_BYTES];
            let length = write_send_message(
                &mut tl,
                peer,
                text,
                random_id,
                disable_notification,
                protect_content,
                reply_to_message_id,
            )?;
            let transport = entry
                .transport
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::InvalidState, length, 0))?;
            let mut result = [0u8; MAX_RESPONSE_BYTES];
            let result_length = transport.call(&tl[..length], &mut result)?;
            write_ok_raw(output, &result[..result_length])
        }
        BotRequest::GetUpdates {
            offset,
            limit,
            timeout,
        } => {
            let _ = (offset, timeout);
            let mut updates = Vec::with_capacity(256);
            updates.extend_from_slice(b"[");
            for (index, update) in entry.updates.iter().take(limit as usize).enumerate() {
                if index != 0 {
                    updates.push(b',');
                }
                updates.extend_from_slice(update);
            }
            updates.push(b']');
            write_ok_raw(output, &updates)
        }
        BotRequest::SetWebhook {
            url,
            drop_pending_updates,
        } => {
            entry.webhook_url = Some(url.into());
            if drop_pending_updates {
                entry.updates.clear();
            }
            write_ok_bool(output, true)
        }
        BotRequest::DeleteWebhook {
            drop_pending_updates,
        } => {
            entry.webhook_url = None;
            if drop_pending_updates {
                entry.updates.clear();
            }
            write_ok_bool(output, true)
        }
        BotRequest::GetWebhookInfo => {
            let mut value = Vec::with_capacity(128);
            value.extend_from_slice(br#"{"url":"#);
            if let Some(url) = entry.webhook_url.as_deref() {
                append_json_string(&mut value, url);
            } else {
                value.push(b'"');
            }
            value
                .extend_from_slice(br#","has_custom_certificate":false,"pending_update_count":0}"#);
            write_ok_raw(output, &value)
        }
        BotRequest::AnswerCallbackQuery {
            callback_query_id,
            text,
            show_alert,
            cache_time,
        } => {
            let _ = (callback_query_id, text, show_alert, cache_time);
            write_ok_bool(output, true)
        }
        BotRequest::GetChat { chat_id } => {
            if chat_id == entry.info.id {
                let mut value = Vec::with_capacity(128);
                value.extend_from_slice(br#"{"id":"#);
                append_i64(&mut value, chat_id);
                value.extend_from_slice(br#","type":"private","username":"#);
                if let Some(username) = entry.info.username.as_deref() {
                    append_json_string(&mut value, username);
                }
                value.extend_from_slice(br#","first_name":"#);
                append_json_string(&mut value, &entry.info.first_name);
                value.extend_from_slice(b"}");
                write_ok_raw(output, &value)
            } else {
                Err(Error::new(ErrorKind::Unsupported, 0, 0))
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, registry: &BotRegistry) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut buffer = [0u8; MAX_HTTP_REQUEST_BYTES];
    let mut length = 0usize;
    let (header_end, content_length) = loop {
        if length == buffer.len() {
            return write_http_error(&mut stream, 413, "request too large");
        }
        let read = stream.read(&mut buffer[length..])?;
        if read == 0 {
            return Ok(());
        }
        length += read;
        if let Some(end) = find_bytes(&buffer[..length], b"\r\n\r\n") {
            let headers = &buffer[..end];
            let content_length = parse_content_length(headers).unwrap_or(0);
            break (end + 4, content_length);
        }
    };
    if content_length > MAX_JSON_BYTES || header_end.saturating_add(content_length) > buffer.len() {
        return write_http_error(&mut stream, 413, "body too large");
    }
    while length < header_end + content_length {
        let read = stream.read(&mut buffer[length..])?;
        if read == 0 {
            return write_http_error(&mut stream, 400, "truncated body");
        }
        length += read;
    }
    let (method, token, api_method) = match parse_target(&buffer[..header_end]) {
        Some(target) => target,
        None => return write_http_error(&mut stream, 404, "invalid Bot API path"),
    };
    if method != "POST" && method != "GET" {
        return write_http_error(&mut stream, 405, "method not allowed");
    }
    let mut response = vec![0u8; MAX_RESPONSE_BYTES];
    let body = &buffer[header_end..header_end + content_length];
    let result = dispatch(registry, token, api_method, body, &mut response);
    let response_length = match result {
        Ok(length) => length,
        Err(error) => {
            let (status, code, description) = map_error(error);
            let length = write_error(&mut response, code, description).unwrap_or(0);
            return write_http_response(&mut stream, status, &response[..length]);
        }
    };
    write_http_response(&mut stream, 200, &response[..response_length])
}

fn parse_target<'a>(headers: &'a [u8]) -> Option<(&'a str, &'a str, &'a str)> {
    let first_line_end = find_bytes(headers, b"\r\n").unwrap_or(headers.len());
    let line = core::str::from_utf8(&headers[..first_line_end]).ok()?;
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let prefix = "/bot";
    let target = target.strip_prefix(prefix)?;
    let slash = target.find('/')?;
    let token = &target[..slash];
    let api_method = target[slash + 1..].split('?').next()?;
    if token.is_empty() || api_method.is_empty() {
        return None;
    }
    Some((method, token, api_method))
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            let name = &line[..colon];
            let value = &line[colon + 1..];
            if name.eq_ignore_ascii_case(b"content-length") {
                return core::str::from_utf8(value.trim_ascii())
                    .ok()?
                    .parse::<usize>()
                    .ok();
            }
        }
    }
    Some(0)
}

fn find_bytes(input: &[u8], needle: &[u8]) -> Option<usize> {
    input
        .windows(needle.len())
        .position(|window| window == needle)
}

fn map_error(error: Error) -> (u16, i32, &'static str) {
    match error.kind {
        ErrorKind::InvalidToken => (401, 401, "Unauthorized"),
        ErrorKind::MethodNotFound => (404, 404, "Method not found"),
        ErrorKind::InvalidJson | ErrorKind::MissingField | ErrorKind::InvalidValue => {
            (400, 400, "Bad Request")
        }
        ErrorKind::Unsupported => (501, 400, "Method is not supported by this profile"),
        ErrorKind::LimitExceeded => (413, 413, "Request is too large"),
        _ => (500, 500, "Internal gateway error"),
    }
}

fn write_http_error(stream: &mut TcpStream, status: u16, description: &str) -> io::Result<()> {
    let body =
        format!("{{\"ok\":false,\"error_code\":{status},\"description\":\"{description}\"}}");
    write_http_response(stream, status, body.as_bytes())
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Error",
    }
}

fn next_random_id() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos() as i64)
        .unwrap_or(0);
    now ^ REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

fn append_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(value.to_string().as_bytes());
}

fn append_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => output.extend_from_slice(b"\\\""),
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            _ => output.push(byte),
        }
    }
    output.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::{BotEntry, BotInfo, BotRegistry, BotTransport, dispatch};

    struct GenericTransport;

    impl BotTransport for GenericTransport {
        fn call(&mut self, _method: &[u8], _output: &mut [u8]) -> trbotapi_core::Result<usize> {
            Err(trbotapi_core::Error::new(
                trbotapi_core::ErrorKind::Unsupported,
                0,
                0,
            ))
        }

        fn call_bot_api(
            &mut self,
            method: &str,
            body: &[u8],
            output: &mut [u8],
        ) -> trbotapi_core::Result<usize> {
            assert_eq!(method, "setChatTitle");
            assert!(body.windows(7).any(|window| window == b"chat_id"));
            let result = b"true";
            output[..result.len()].copy_from_slice(result);
            Ok(result.len())
        }
    }

    #[test]
    fn registry_dispatches_get_me_without_network() {
        let registry = BotRegistry::new();
        registry.register(
            "1:secret".into(),
            BotEntry::new(BotInfo {
                id: 7,
                first_name: "TR Bot".into(),
                username: Some("tr_bot".into()),
            }),
        );
        let mut output = [0u8; 512];
        let length = dispatch(&registry, "1:secret", "getMe", b"{}", &mut output).expect("getMe");
        let body = core::str::from_utf8(&output[..length]).expect("json");
        assert!(body.contains("tr_bot"));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_forwards_every_catalogued_method_to_transport() {
        let registry = BotRegistry::new();
        registry.register(
            "1:secret".into(),
            BotEntry::new(BotInfo {
                id: 7,
                first_name: "TR Bot".into(),
                username: Some("tr_bot".into()),
            })
            .with_transport(Box::new(GenericTransport)),
        );
        let mut output = [0u8; 512];
        let length = dispatch(
            &registry,
            "1:secret",
            "setChatTitle",
            br#"{"chat_id":-7,"title":"New title"}"#,
            &mut output,
        )
        .expect("generic method");
        assert_eq!(&output[..length], br#"{"ok":true,"result":true}"#);
    }
}
