#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
//! Small, allocation-free pieces of a Telegram Bot API gateway.
//!
//! The crate deliberately stops at the protocol boundary.  An HTTP acceptor,
//! bot-session registry, MTProto scheduler and update queue belong to the
//! server crate or to the embedding application.  Requests borrow the caller's
//! body and TL writers write into caller-owned buffers.

use core::str;

use trlib_core::api::{InputPeer, write_send_text_reply};
use trlib_core::generated::{auth::AUTH_IMPORT_BOT_AUTHORIZATION, users::USERS_GET_FULL_USER};
use trlib_core::tl::{ConstructorId, Cursor, Writer};

mod bot_methods;

use bot_methods::is_typed_method;
pub use bot_methods::{BOT_API_METHOD_COUNT, BOT_API_METHODS, is_bot_api_method};

/// Maximum JSON body accepted by the reference edge.
pub const MAX_JSON_BYTES: usize = 64 * 1024;
/// Maximum response body emitted by the reference edge.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// MTProto `rpc_result` constructor.
pub const RPC_RESULT: ConstructorId = ConstructorId::new(0xf35c6d01);
/// MTProto `msg_container` constructor.
pub const MSG_CONTAINER: ConstructorId = ConstructorId::new(0x73f1f8dc);
/// Bare MTProto vector constructor.
pub const VECTOR: ConstructorId = ConstructorId::new(0x1cb5c415);

/// Error classes shared by the no-std core and the std HTTP edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorKind {
    /// The input is not a bounded JSON object.
    InvalidJson = 1,
    /// A JSON field has the wrong type or range.
    InvalidValue = 2,
    /// A required field is absent.
    MissingField = 3,
    /// The URL method is not part of this build.
    MethodNotFound = 4,
    /// The method is known but not implemented by this gateway profile.
    Unsupported = 5,
    /// A configured fixed limit was exceeded.
    LimitExceeded = 6,
    /// The caller-owned output buffer is too small.
    OutputTooSmall = 7,
    /// The bot token or session is not available.
    InvalidToken = 8,
    /// A backend/session state transition is invalid.
    InvalidState = 9,
    /// A TRLib wire operation failed.
    Wire = 10,
}

/// Compact, allocation-free error value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Error {
    /// Error class.
    pub kind: ErrorKind,
    /// Input offset or output position where the error was detected.
    pub offset: u32,
    /// Small detail value, normally an expected length or protocol code.
    pub detail: u32,
}

impl Error {
    /// Creates an error with a source offset and detail value.
    pub const fn new(kind: ErrorKind, offset: usize, detail: u32) -> Self {
        Self {
            kind,
            offset: if offset > u32::MAX as usize {
                u32::MAX
            } else {
                offset as u32
            },
            detail,
        }
    }

    const fn invalid_json(offset: usize) -> Self {
        Self::new(ErrorKind::InvalidJson, offset, 0)
    }

    const fn missing(offset: usize) -> Self {
        Self::new(ErrorKind::MissingField, offset, 0)
    }
}

/// Result type used by this crate.
pub type Result<T> = core::result::Result<T, Error>;

impl From<trlib_core::Error> for Error {
    fn from(error: trlib_core::Error) -> Self {
        Self::new(ErrorKind::Wire, error.offset() as usize, error.detail())
    }
}

/// A bounded Telegram Bot API request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BotRequest<'a> {
    /// A known Bot API method whose JSON is forwarded without an intermediate
    /// AST.  The transport is responsible for parameter-to-MTProto mapping and
    /// for writing the result object (without the outer `ok` envelope).
    Generic {
        /// Method spelling as it appeared in the request path.
        method: &'a str,
        /// Borrowed JSON object supplied by the HTTP caller.
        body: &'a [u8],
    },
    /// `getMe`.
    GetMe,
    /// Text `sendMessage` with standard boolean options and reply target.
    SendMessage {
        /// Bot API chat identifier.  String usernames are rejected until a
        /// username resolver is configured by the server.
        chat_id: i64,
        /// UTF-8 message text.
        text: &'a str,
        /// Optional forum topic identifier.
        message_thread_id: Option<i32>,
        /// Disable notification.
        disable_notification: bool,
        /// Protect content from forwarding.
        protect_content: bool,
        /// Optional reply message identifier.
        reply_to_message_id: Option<i32>,
    },
    /// `getUpdates`; queue ownership remains with the server.
    GetUpdates {
        /// First update identifier to return.
        offset: i64,
        /// Maximum number of updates.
        limit: u16,
        /// Long-poll timeout in seconds.
        timeout: u32,
    },
    /// `setWebhook`; the URL is stored by the server control plane.
    SetWebhook {
        /// HTTPS callback URL.
        url: &'a str,
        /// Whether queued updates should be discarded.
        drop_pending_updates: bool,
    },
    /// `deleteWebhook`.
    DeleteWebhook {
        /// Whether queued updates should be discarded.
        drop_pending_updates: bool,
    },
    /// `getWebhookInfo`.
    GetWebhookInfo,
    /// `answerCallbackQuery` without a URL or game redirect.
    AnswerCallbackQuery {
        /// Callback query identifier.
        callback_query_id: &'a str,
        /// Optional alert text.
        text: Option<&'a str>,
        /// Whether Telegram should show an alert.
        show_alert: bool,
        /// Client-side cache lifetime.
        cache_time: u32,
    },
    /// `getChat` for an integer dialog identifier.
    GetChat {
        /// Bot API chat identifier.
        chat_id: i64,
    },
}

/// Parses one Bot API method body without an allocation or a JSON AST.
///
/// Escaped JSON strings are rejected intentionally.  A gateway that needs
/// arbitrary escaped text can decode into an application-owned scratch buffer
/// before calling this function.
pub fn parse_request<'a>(method: &'a str, input: &'a [u8]) -> Result<BotRequest<'a>> {
    let input = if input.is_empty() { b"{}" } else { input };
    if input.len() > MAX_JSON_BYTES {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            0,
            MAX_JSON_BYTES as u32,
        ));
    }
    if !is_bot_api_method(method) {
        return Err(Error::new(ErrorKind::MethodNotFound, 0, 0));
    }
    if !is_typed_method(method) {
        validate_json_object(input)?;
        return Ok(BotRequest::Generic {
            method,
            body: input,
        });
    }
    let mut cursor = JsonCursor::new(input);
    cursor.expect(b'{')?;

    let mut chat_id = None;
    let mut text = None;
    let mut message_thread_id = None;
    let mut disable_notification = false;
    let mut protect_content = false;
    let mut reply_to_message_id = None;
    let mut offset = 0i64;
    let mut limit = 100u16;
    let mut timeout = 0u32;
    let mut url = None;
    let mut drop_pending_updates = false;
    let mut callback_query_id = None;
    let mut callback_text = None;
    let mut show_alert = false;
    let mut cache_time = 0u32;

    if !cursor.consume(b'}')? {
        loop {
            let key = cursor.read_string()?;
            cursor.expect(b':')?;
            match key {
                "chat_id" => chat_id = Some(cursor.read_int64_or_string()?),
                "text" => {
                    let value = cursor.read_string()?;
                    text = Some(value);
                    callback_text = Some(value);
                }
                "message_thread_id" => message_thread_id = Some(cursor.read_i32()?),
                "disable_notification" => disable_notification = cursor.read_bool()?,
                "protect_content" => protect_content = cursor.read_bool()?,
                "reply_to_message_id" => reply_to_message_id = Some(cursor.read_i32()?),
                "reply_parameters" => {
                    if let Some(value) = cursor.read_optional_object()? {
                        reply_to_message_id = Some(value);
                    }
                }
                "offset" => offset = cursor.read_i64()?,
                "limit" => {
                    let value = cursor.read_i64()?;
                    limit = u16::try_from(value)
                        .map_err(|_| Error::new(ErrorKind::InvalidValue, cursor.position(), 100))?;
                }
                "timeout" => {
                    let value = cursor.read_i64()?;
                    timeout = u32::try_from(value)
                        .map_err(|_| Error::new(ErrorKind::InvalidValue, cursor.position(), 0))?;
                }
                "url" => url = Some(cursor.read_string()?),
                "drop_pending_updates" => drop_pending_updates = cursor.read_bool()?,
                "callback_query_id" => callback_query_id = Some(cursor.read_string()?),
                "show_alert" => show_alert = cursor.read_bool()?,
                "cache_time" => {
                    let value = cursor.read_i64()?;
                    cache_time = u32::try_from(value)
                        .map_err(|_| Error::new(ErrorKind::InvalidValue, cursor.position(), 0))?;
                }
                _ => cursor.skip_value()?,
            }
            if cursor.consume(b'}')? {
                break;
            }
            cursor.expect(b',')?;
        }
    }
    cursor.finish()?;

    if method.eq_ignore_ascii_case("getMe") {
        Ok(BotRequest::GetMe)
    } else if method.eq_ignore_ascii_case("sendMessage") {
        Ok(BotRequest::SendMessage {
            chat_id: chat_id.ok_or_else(|| Error::missing(0))?,
            text: text.ok_or_else(|| Error::missing(0))?,
            message_thread_id,
            disable_notification,
            protect_content,
            reply_to_message_id,
        })
    } else if method.eq_ignore_ascii_case("getUpdates") {
        if limit == 0 || limit > 100 {
            return Err(Error::new(ErrorKind::InvalidValue, 0, 100));
        }
        Ok(BotRequest::GetUpdates {
            offset,
            limit,
            timeout,
        })
    } else if method.eq_ignore_ascii_case("setWebhook") {
        Ok(BotRequest::SetWebhook {
            url: url.ok_or_else(|| Error::missing(0))?,
            drop_pending_updates,
        })
    } else if method.eq_ignore_ascii_case("deleteWebhook") {
        Ok(BotRequest::DeleteWebhook {
            drop_pending_updates,
        })
    } else if method.eq_ignore_ascii_case("getWebhookInfo") {
        Ok(BotRequest::GetWebhookInfo)
    } else if method.eq_ignore_ascii_case("answerCallbackQuery") {
        Ok(BotRequest::AnswerCallbackQuery {
            callback_query_id: callback_query_id.ok_or_else(|| Error::missing(0))?,
            text: callback_text,
            show_alert,
            cache_time,
        })
    } else if method.eq_ignore_ascii_case("getChat") {
        Ok(BotRequest::GetChat {
            chat_id: chat_id.ok_or_else(|| Error::missing(0))?,
        })
    } else {
        // `is_typed_method` and the branches above intentionally stay in sync;
        // reaching this arm means a new typed method was added without its
        // parser, which is an unsupported build error rather than a 404.
        Err(Error::new(ErrorKind::Unsupported, 0, 0))
    }
}

fn validate_json_object(input: &[u8]) -> Result<()> {
    let mut cursor = JsonCursor::new(input);
    cursor.expect(b'{')?;
    if !cursor.consume(b'}')? {
        loop {
            cursor.skip_string()?;
            cursor.expect(b':')?;
            cursor.skip_value()?;
            if cursor.consume(b'}')? {
                break;
            }
            cursor.expect(b',')?;
        }
    }
    cursor.finish()
}

/// Writes a successful empty Bot API response.
pub fn write_ok_empty(output: &mut [u8]) -> Result<usize> {
    write_all(output, br#"{"ok":true,"result":true}"#)
}

/// Writes a successful boolean response.
pub fn write_ok_bool(output: &mut [u8], value: bool) -> Result<usize> {
    if value {
        write_ok_empty(output)
    } else {
        write_all(output, br#"{"ok":true,"result":false}"#)
    }
}

/// Writes a successful empty update array.
pub fn write_ok_updates_empty(output: &mut [u8]) -> Result<usize> {
    write_all(output, br#"{"ok":true,"result":[]}"#)
}

/// Writes a successful raw JSON result supplied by a TL decoder.
pub fn write_ok_raw(output: &mut [u8], result: &[u8]) -> Result<usize> {
    let prefix = br#"{"ok":true,"result":"#;
    let suffix = b"}";
    if prefix.len() + result.len() + suffix.len() > output.len() {
        return Err(Error::new(
            ErrorKind::OutputTooSmall,
            0,
            (prefix.len() + result.len() + suffix.len()) as u32,
        ));
    }
    output[..prefix.len()].copy_from_slice(prefix);
    output[prefix.len()..prefix.len() + result.len()].copy_from_slice(result);
    output[prefix.len() + result.len()..prefix.len() + result.len() + 1].copy_from_slice(suffix);
    Ok(prefix.len() + result.len() + suffix.len())
}

/// Writes the Bot API error envelope.
pub fn write_error(output: &mut [u8], code: i32, description: &str) -> Result<usize> {
    let prefix = br#"{"ok":false,"error_code":"#;
    let middle = br#","description":"#;
    let mut writer = SliceWriter::new(output);
    writer.write(prefix)?;
    writer.write_i64(i64::from(code))?;
    writer.write(middle)?;
    writer.write_json_string(description)?;
    writer.write(b"}")?;
    Ok(writer.position())
}

/// Writes a minimal Bot API `User` object for `getMe`.
pub fn write_ok_user(
    output: &mut [u8],
    id: i64,
    is_bot: bool,
    first_name: &str,
    username: Option<&str>,
) -> Result<usize> {
    let mut writer = SliceWriter::new(output);
    writer.write(br#"{"ok":true,"result":{"id":"#)?;
    let mut id_buffer = [0u8; 20];
    let id_length = decimal_i64(id, &mut id_buffer);
    writer.write(&id_buffer[..id_length])?;
    writer.write(br#","is_bot":"#)?;
    writer.write_bool(is_bot)?;
    writer.write(br#", "#)?;
    writer.write_json_key_value("first_name", first_name)?;
    if let Some(username) = username {
        writer.write(&[b','])?;
        writer.write_json_key_value("username", username)?;
    }
    writer.write(b"}}")?;
    Ok(writer.position())
}

/// Maps a Bot API dialog id to a TRLib input peer when the access hash is
/// available from the bot's update/entity cache.
pub fn input_peer_for_chat(
    chat_id: i64,
    bot_user_id: Option<i64>,
    access_hash: Option<i64>,
) -> Result<InputPeer> {
    if bot_user_id == Some(chat_id) {
        return Ok(InputPeer::SelfPeer);
    }
    if chat_id < 0 && chat_id > -1_000_000_000_000 {
        return Ok(InputPeer::Chat { chat_id: -chat_id });
    }
    let access_hash = access_hash.ok_or_else(|| Error::new(ErrorKind::Unsupported, 0, 0))?;
    if chat_id <= -1_000_000_000_000 {
        return Ok(InputPeer::Channel {
            channel_id: -1_000_000_000_000 - chat_id,
            access_hash,
        });
    }
    if chat_id > 0 {
        return Ok(InputPeer::User {
            user_id: chat_id,
            access_hash,
        });
    }
    Err(Error::new(ErrorKind::InvalidValue, 0, 0))
}

/// Writes `auth.importBotAuthorization` into a caller-owned TL buffer.
pub fn write_import_bot_authorization(
    output: &mut [u8],
    api_id: i32,
    api_hash: &str,
    bot_token: &str,
) -> Result<usize> {
    let mut writer = Writer::new(output);
    writer
        .write_constructor(AUTH_IMPORT_BOT_AUTHORIZATION)
        .map_err(Error::from)?;
    writer.write_i32(0).map_err(Error::from)?;
    writer.write_i32(api_id).map_err(Error::from)?;
    writer.write_string(api_hash).map_err(Error::from)?;
    writer.write_string(bot_token).map_err(Error::from)?;
    Ok(writer.position())
}

/// Writes `users.getFullUser(inputUserSelf)` into a caller-owned TL buffer.
pub fn write_get_me(output: &mut [u8]) -> Result<usize> {
    let mut writer = Writer::new(output);
    writer
        .write_constructor(USERS_GET_FULL_USER)
        .map_err(Error::from)?;
    writer
        .write_constructor(trlib_core::generated::common::INPUT_USER_SELF)
        .map_err(Error::from)?;
    Ok(writer.position())
}

/// Writes the text-only MTProto `messages.sendMessage` request.
pub fn write_send_message(
    output: &mut [u8],
    peer: InputPeer,
    text: &str,
    random_id: i64,
    disable_notification: bool,
    protect_content: bool,
    reply_to_message_id: Option<i32>,
) -> Result<usize> {
    let mut writer = Writer::new(output);
    let mut options = trlib_core::api::SendMessageOptions::EMPTY;
    if disable_notification {
        options = options.silent();
    }
    if protect_content {
        options = options.protect_content();
    }
    write_send_text_reply(
        &mut writer,
        peer,
        text,
        random_id,
        options,
        reply_to_message_id,
    )
    .map_err(Error::from)?;
    Ok(writer.position())
}

/// Returns the body inside an MTProto `rpc_result`, walking a bounded message
/// container when Telegram delivered service messages before the response.
pub fn rpc_result_body(input: &[u8]) -> Result<&[u8]> {
    let mut cursor = Cursor::new(input);
    match cursor.read_constructor().map_err(Error::from)? {
        RPC_RESULT => {
            cursor.read_i64().map_err(Error::from)?;
            Ok(cursor.remaining())
        }
        MSG_CONTAINER => {
            let first = cursor.read_u32().map_err(Error::from)?;
            let count = if first == VECTOR.get() {
                cursor.read_u32().map_err(Error::from)?
            } else {
                first
            };
            if count > 64 {
                return Err(Error::new(ErrorKind::LimitExceeded, 0, count));
            }
            for _ in 0..count {
                cursor.read_u64().map_err(Error::from)?;
                cursor.read_u32().map_err(Error::from)?;
                let length = cursor.read_u32().map_err(Error::from)? as usize;
                let message = cursor.take(length).map_err(Error::from)?;
                if let Ok(result) = rpc_result_body(message) {
                    return Ok(result);
                }
            }
            Err(Error::new(ErrorKind::InvalidState, 0, 0))
        }
        _ => Err(Error::new(ErrorKind::Wire, 0, 0)),
    }
}

fn write_all(output: &mut [u8], value: &[u8]) -> Result<usize> {
    if value.len() > output.len() {
        return Err(Error::new(ErrorKind::OutputTooSmall, 0, value.len() as u32));
    }
    output[..value.len()].copy_from_slice(value);
    Ok(value.len())
}

struct SliceWriter<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn write(&mut self, value: &[u8]) -> Result<()> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| Error::new(ErrorKind::OutputTooSmall, self.position, u32::MAX))?;
        if end > self.output.len() {
            return Err(Error::new(
                ErrorKind::OutputTooSmall,
                self.position,
                value.len() as u32,
            ));
        }
        self.output[self.position..end].copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn write_i64(&mut self, value: i64) -> Result<()> {
        let mut buffer = [0u8; 20];
        let len = decimal_i64(value, &mut buffer);
        self.write(&buffer[..len])
    }

    fn write_bool(&mut self, value: bool) -> Result<()> {
        self.write(if value { b"true" } else { b"false" })
    }

    fn write_json_string(&mut self, value: &str) -> Result<()> {
        self.write(b"\"")?;
        for byte in value.bytes() {
            match byte {
                b'"' => self.write(b"\\\"")?,
                b'\\' => self.write(b"\\\\")?,
                b'\n' => self.write(b"\\n")?,
                b'\r' => self.write(b"\\r")?,
                b'\t' => self.write(b"\\t")?,
                0..=0x1f => {
                    let hex = [
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        hex_digit(byte >> 4),
                        hex_digit(byte & 0xf),
                    ];
                    self.write(&hex)?;
                }
                _ => self.write(&[byte])?,
            }
        }
        self.write(b"\"")
    }

    fn write_json_key_value(&mut self, key: &str, value: &str) -> Result<()> {
        self.write_json_string(key)?;
        self.write(b":")?;
        self.write_json_string(value)
    }
}

fn decimal_i64(value: i64, output: &mut [u8; 20]) -> usize {
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut index = output.len();
    if magnitude == 0 {
        index -= 1;
        output[index] = b'0';
    } else {
        while magnitude != 0 {
            index -= 1;
            output[index] = b'0' + (magnitude % 10) as u8;
            magnitude /= 10;
        }
    }
    if negative {
        index -= 1;
        output[index] = b'-';
    }
    let len = output.len() - index;
    output.copy_within(index.., 0);
    len
}

const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

struct JsonCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> JsonCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_space();
        self.input.get(self.position).copied()
    }

    fn skip_space(&mut self) {
        while matches!(
            self.input.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }

    fn expect(&mut self, value: u8) -> Result<()> {
        self.skip_space();
        if self.input.get(self.position) == Some(&value) {
            self.position += 1;
            Ok(())
        } else {
            Err(Error::invalid_json(self.position))
        }
    }

    fn consume(&mut self, value: u8) -> Result<bool> {
        self.skip_space();
        if self.input.get(self.position) == Some(&value) {
            self.position += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn finish(&mut self) -> Result<()> {
        self.skip_space();
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(Error::invalid_json(self.position))
        }
    }

    fn read_string(&mut self) -> Result<&'a str> {
        self.expect(b'"')?;
        let start = self.position;
        while let Some(byte) = self.input.get(self.position).copied() {
            match byte {
                b'"' => {
                    let value = str::from_utf8(&self.input[start..self.position])
                        .map_err(|_| Error::invalid_json(start))?;
                    self.position += 1;
                    if value.as_bytes().contains(&b'\\') {
                        return Err(Error::new(ErrorKind::Unsupported, start, 0));
                    }
                    return Ok(value);
                }
                b'\\' | 0..=0x1f => return Err(Error::invalid_json(self.position)),
                _ => self.position += 1,
            }
        }
        Err(Error::invalid_json(self.position))
    }

    fn skip_string(&mut self) -> Result<()> {
        self.expect(b'"')?;
        while let Some(byte) = self.input.get(self.position).copied() {
            self.position += 1;
            match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    let escaped = self
                        .input
                        .get(self.position)
                        .copied()
                        .ok_or_else(|| Error::invalid_json(self.position))?;
                    self.position += 1;
                    if escaped == b'u' {
                        for _ in 0..4 {
                            let digit = self
                                .input
                                .get(self.position)
                                .copied()
                                .ok_or_else(|| Error::invalid_json(self.position))?;
                            if !digit.is_ascii_hexdigit() {
                                return Err(Error::invalid_json(self.position));
                            }
                            self.position += 1;
                        }
                    } else if !matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        return Err(Error::invalid_json(self.position - 1));
                    }
                }
                0..=0x1f => return Err(Error::invalid_json(self.position - 1)),
                _ => {}
            }
        }
        Err(Error::invalid_json(self.position))
    }

    fn read_bool(&mut self) -> Result<bool> {
        self.skip_space();
        if self.input[self.position..].starts_with(b"true") {
            self.position += 4;
            Ok(true)
        } else if self.input[self.position..].starts_with(b"false") {
            self.position += 5;
            Ok(false)
        } else {
            Err(Error::invalid_json(self.position))
        }
    }

    fn read_i64(&mut self) -> Result<i64> {
        self.skip_space();
        let start = self.position;
        if self.input.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        let digits = self.position;
        while matches!(self.input.get(self.position), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        if self.position == digits {
            return Err(Error::invalid_json(start));
        }
        let value = str::from_utf8(&self.input[start..self.position])
            .map_err(|_| Error::invalid_json(start))?
            .parse::<i64>()
            .map_err(|_| Error::new(ErrorKind::InvalidValue, start, 0))?;
        Ok(value)
    }

    fn read_int64_or_string(&mut self) -> Result<i64> {
        if self.peek() == Some(b'"') {
            let value = self.read_string()?;
            value
                .parse::<i64>()
                .map_err(|_| Error::new(ErrorKind::Unsupported, self.position, 0))
        } else {
            self.read_i64()
        }
    }

    fn read_i32(&mut self) -> Result<i32> {
        let value = self.read_i64()?;
        i32::try_from(value).map_err(|_| Error::new(ErrorKind::InvalidValue, self.position, 0))
    }

    fn read_optional_object(&mut self) -> Result<Option<i32>> {
        if self.consume_literal(b"null")? {
            return Ok(None);
        }
        self.expect(b'{')?;
        let mut message_id = None;
        if !self.consume(b'}')? {
            loop {
                let key = self.read_string()?;
                self.expect(b':')?;
                if key == "message_id" {
                    message_id = Some(self.read_i32()?);
                } else {
                    self.skip_value()?;
                }
                if self.consume(b'}')? {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(message_id)
    }

    fn consume_literal(&mut self, value: &[u8]) -> Result<bool> {
        self.skip_space();
        if self.input[self.position..].starts_with(value) {
            self.position += value.len();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn skip_value(&mut self) -> Result<()> {
        match self.peek() {
            Some(b'"') => self.skip_string(),
            Some(b'{') => {
                self.expect(b'{')?;
                if !self.consume(b'}')? {
                    loop {
                        self.skip_string()?;
                        self.expect(b':')?;
                        self.skip_value()?;
                        if self.consume(b'}')? {
                            break;
                        }
                        self.expect(b',')?;
                    }
                }
                Ok(())
            }
            Some(b'[') => {
                self.expect(b'[')?;
                if !self.consume(b']')? {
                    loop {
                        self.skip_value()?;
                        if self.consume(b']')? {
                            break;
                        }
                        self.expect(b',')?;
                    }
                }
                Ok(())
            }
            Some(b't') => self.expect_literal(b"true"),
            Some(b'f') => self.expect_literal(b"false"),
            Some(b'n') => self.expect_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.read_i64().map(|_| ()),
            _ => Err(Error::invalid_json(self.position)),
        }
    }

    fn expect_literal(&mut self, value: &[u8]) -> Result<()> {
        if self.consume_literal(value)? {
            Ok(())
        } else {
            Err(Error::invalid_json(self.position))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BOT_API_METHOD_COUNT, BotRequest, ErrorKind, is_bot_api_method, parse_request, write_error,
        write_import_bot_authorization, write_ok_user,
    };

    #[test]
    fn parses_bounded_send_message_shape() {
        let request = parse_request(
            "sendMessage",
            br#"{"chat_id":-42,"text":"hello","disable_notification":true,"reply_parameters":{"message_id":7}}"#,
        )
        .expect("request");
        assert_eq!(
            request,
            BotRequest::SendMessage {
                chat_id: -42,
                text: "hello",
                message_thread_id: None,
                disable_notification: true,
                protect_content: false,
                reply_to_message_id: Some(7),
            }
        );
    }

    #[test]
    fn rejects_escaped_typed_strings_and_limits_updates() {
        assert_eq!(
            parse_request("sendMessage", br#"{"chat_id":7,"text":"a\\nb"}"#)
                .expect_err("escape")
                .kind,
            ErrorKind::InvalidJson
        );
        assert_eq!(
            parse_request("getUpdates", br#"{"limit":101}"#)
                .expect_err("limit")
                .kind,
            ErrorKind::InvalidValue
        );
    }

    #[test]
    fn routes_the_full_method_catalogue_without_copying_json() {
        assert_eq!(BOT_API_METHOD_COUNT, 185);
        assert!(is_bot_api_method("sendRichMessage"));
        assert!(is_bot_api_method("SENDRICHMESSAGE"));
        assert_eq!(
            parse_request("logOut", b""),
            Ok(BotRequest::Generic {
                method: "logOut",
                body: b"{}"
            })
        );
        let request = parse_request(
            "setChatTitle",
            br#"{"chat_id":-7,"title":"escaped \"title\""}"#,
        )
        .expect("generic method");
        assert_eq!(
            request,
            BotRequest::Generic {
                method: "setChatTitle",
                body: br#"{"chat_id":-7,"title":"escaped \"title\""}"#,
            }
        );
    }

    #[test]
    fn writes_json_and_bot_auth_prefixes() {
        let mut output = [0u8; 512];
        let length = write_ok_user(&mut output, 7, true, "bot", Some("example_bot")).expect("user");
        assert!(
            core::str::from_utf8(&output[..length])
                .expect("utf8")
                .contains("example_bot")
        );
        let error = write_error(&mut output, 400, "bad request").expect("error");
        assert!(
            core::str::from_utf8(&output[..error])
                .expect("utf8")
                .contains("\"error_code\":400")
        );
        let auth = write_import_bot_authorization(&mut output, 1, "hash", "1:token").expect("auth");
        assert!(auth > 16);
    }
}
