//! A small Test-DC MTProto transport used by the reference server.
//!
//! It intentionally uses the authorization-key implementation from TRLib and
//! keeps production DC key provisioning outside this crate.  A production
//! reactor should implement `BotTransport` with shared connection pools rather
//! than creating one blocking `TcpStream` per HTTP worker.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use trbotapi_core::{
    Error, ErrorKind, Result, input_peer_for_chat, rpc_result_body, write_import_bot_authorization,
};
use trlib_core::api::{
    ApiContext, parse_auth_response, write_delete_messages, write_edit_message_text,
    write_init_connection_prefix, write_log_out,
};
use trlib_core::auth_key::{AuthKeyHandshake, AuthKeyMaterial, RandomSource};
use trlib_core::crypto::{AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto};
use trlib_core::generated::messages::{
    MESSAGES_DELETE_CHAT_USER, MESSAGES_EDIT_CHAT_ABOUT, MESSAGES_EDIT_CHAT_TITLE,
    MESSAGES_EDIT_MESSAGE, MESSAGES_FORWARD_MESSAGES, MESSAGES_GET_CUSTOM_EMOJI_DOCUMENTS,
    MESSAGES_GET_FULL_CHAT, MESSAGES_GET_STICKER_SET, MESSAGES_SEND_MEDIA, MESSAGES_SEND_MESSAGE,
    MESSAGES_SEND_MULTI_MEDIA, MESSAGES_SEND_REACTION, MESSAGES_SET_INLINE_BOT_RESULTS,
    MESSAGES_SET_TYPING, MESSAGES_STICKER_SET, MESSAGES_UNPIN_ALL_MESSAGES,
    MESSAGES_UPDATE_PINNED_MESSAGE,
};
use trlib_core::generated::{
    INPUT_BOT_INLINE_MESSAGE_TEXT, INPUT_BOT_INLINE_RESULT, INPUT_GEO_POINT, INPUT_MEDIA_CONTACT,
    INPUT_MEDIA_DICE, INPUT_MEDIA_DOCUMENT_EXTERNAL, INPUT_MEDIA_GEO_POINT,
    INPUT_MEDIA_PHOTO_EXTERNAL, INPUT_MEDIA_POLL, INPUT_REPLY_TO_MESSAGE, INPUT_SINGLE_MEDIA,
    INPUT_STICKER_SET_SHORT_NAME, INPUT_USER_SELF, KEYBOARD_BUTTON_CALLBACK, KEYBOARD_BUTTON_ROW,
    KEYBOARD_BUTTON_URL, MESSAGE_ENTITY_BLOCKQUOTE, MESSAGE_ENTITY_BOLD,
    MESSAGE_ENTITY_BOT_COMMAND, MESSAGE_ENTITY_CASHTAG, MESSAGE_ENTITY_CODE,
    MESSAGE_ENTITY_CUSTOM_EMOJI, MESSAGE_ENTITY_EMAIL, MESSAGE_ENTITY_HASHTAG,
    MESSAGE_ENTITY_ITALIC, MESSAGE_ENTITY_MENTION, MESSAGE_ENTITY_MENTION_NAME,
    MESSAGE_ENTITY_PHONE, MESSAGE_ENTITY_PRE, MESSAGE_ENTITY_SPOILER, MESSAGE_ENTITY_STRIKE,
    MESSAGE_ENTITY_TEXT_URL, MESSAGE_ENTITY_UNDERLINE, MESSAGE_ENTITY_URL, POLL, POLL_ANSWER,
    REACTION_EMOJI, REPLY_INLINE_MARKUP, SEND_MESSAGE_CANCEL_ACTION,
    SEND_MESSAGE_CHOOSE_CONTACT_ACTION, SEND_MESSAGE_CHOOSE_STICKER_ACTION,
    SEND_MESSAGE_GEO_LOCATION_ACTION, SEND_MESSAGE_RECORD_AUDIO_ACTION,
    SEND_MESSAGE_RECORD_VIDEO_ACTION, SEND_MESSAGE_TYPING_ACTION, SEND_MESSAGE_UPLOAD_AUDIO_ACTION,
    SEND_MESSAGE_UPLOAD_DOCUMENT_ACTION, SEND_MESSAGE_UPLOAD_PHOTO_ACTION,
    SEND_MESSAGE_UPLOAD_VIDEO_ACTION, STICKER_SET, TEXT_WITH_ENTITIES,
};
use trlib_core::mtproto::{
    ExternalEnvelope, OutboundMessage, encode_encrypted, parse_decrypted, parse_external,
};
use trlib_core::tl::{ConstructorId, Cursor, Writer, schema};
use trlib_core::transport::{Framing, Intermediate};

use crate::BotTransport;

const UPDATE_MESSAGE_ID: ConstructorId = ConstructorId::new(0x4e90bfd6);
const UPDATE_SHORT_SENT_MESSAGE: ConstructorId = ConstructorId::new(0x9015e101);
const UPDATES: ConstructorId = ConstructorId::new(0x74ae4240);
const UPDATES_COMBINED: ConstructorId = ConstructorId::new(0x725b04c3);
const VECTOR: ConstructorId = ConstructorId::new(0x1cb5c415);
const INPUT_PEER_SELF: ConstructorId = ConstructorId::new(0x7da07ec9);
const INPUT_PEER_USER: ConstructorId = ConstructorId::new(0xdde8a54c);
const INPUT_PEER_CHAT: ConstructorId = ConstructorId::new(0x35a95cb9);
const INPUT_PEER_CHANNEL: ConstructorId = ConstructorId::new(0x20adaef8);
const BOOL_TRUE: ConstructorId = ConstructorId::new(0x997275b5);
const BOOL_FALSE: ConstructorId = ConstructorId::new(0xbc799737);
const MESSAGES_CHAT_FULL: ConstructorId = ConstructorId::new(0xe5d7d19c);
const CHAT_FULL: ConstructorId = ConstructorId::new(0x2633421b);
const CHAT_PARTICIPANTS: ConstructorId = ConstructorId::new(0x3cbc93f8);
const CHAT_PARTICIPANTS_FORBIDDEN: ConstructorId = ConstructorId::new(0x8763d3e1);

const MAX_FRAME: usize = 1 << 20;

/// Blocking Test-DC transport.  It is useful for smoke tests and small
/// deployments; large deployments should provide an evented implementation.
pub struct TestDcTransport {
    stream: TcpStream,
    codec: Intermediate,
    material: AuthKeyMaterial,
    session_id: u64,
    sequence: u32,
    random: OsRandom,
    bot_id: i64,
}

impl TestDcTransport {
    /// Associates the transport with the bot user id used for `inputPeerSelf`.
    pub fn with_bot_id(mut self, bot_id: i64) -> Self {
        self.bot_id = bot_id;
        self
    }

    /// Authenticates a bot on Test DC 2 using `auth.importBotAuthorization`.
    pub fn connect(
        api_id: i32,
        api_hash: &str,
        bot_token: &str,
        address: SocketAddr,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 1))?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_nodelay(true).ok();
        let codec = Intermediate;
        stream
            .write_all(codec.init_bytes())
            .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 2))?;

        let mut random = OsRandom;
        let mut handshake = AuthKeyHandshake::new_test_dc(&mut random, 2)?;
        let mut body = [0u8; 4096];
        let mut frame = vec![0u8; MAX_FRAME];
        let request_len = handshake.write_req_pq(&mut body)?;
        send_plain(&mut stream, &codec, &body[..request_len])?;
        let frame_len = receive_frame(&mut stream, &codec, &mut frame)?;
        let body_len =
            handshake.accept_res_pq(plain_body(&frame[..frame_len])?, &mut random, &mut body)?;
        send_plain(&mut stream, &codec, &body[..body_len])?;
        let frame_len = receive_frame(&mut stream, &codec, &mut frame)?;
        let body_len =
            handshake.accept_server_dh(plain_body(&frame[..frame_len])?, &mut random, &mut body)?;
        send_plain(&mut stream, &codec, &body[..body_len])?;
        let frame_len = receive_frame(&mut stream, &codec, &mut frame)?;
        let material = handshake.finish(plain_body(&frame[..frame_len])?)?;

        let mut value = Self {
            stream,
            codec,
            material,
            session_id: random_u64(&mut random)?,
            sequence: 1,
            random,
            bot_id: 0,
        };
        // Telegram requires the first encrypted RPC after the key exchange to
        // initialize the application connection.  Wrapping the bot import in
        // invokeWithLayer(initConnection(...)) also keeps the MTProto path
        // compatible with the official Test DC (otherwise it returns
        // CONNECTION_NOT_INITED before looking at the token).
        let mut import = [0u8; 4096];
        let mut writer = Writer::new(&mut import);
        let context = ApiContext::new(
            api_id,
            api_hash,
            "trbotapi",
            "linux",
            env!("CARGO_PKG_VERSION"),
            "en",
            "",
            "en",
        );
        write_init_connection_prefix(&mut writer, context).map_err(Error::from)?;
        let import_start = writer.position();
        drop(writer);
        let import_len = write_import_bot_authorization(
            &mut import[import_start..],
            api_id,
            api_hash,
            bot_token,
        )?;
        let request_len = import_start + import_len;
        let mut result = vec![0u8; MAX_FRAME];
        let result_len = value.call_raw(&import[..request_len], &mut result)?;
        match parse_auth_response(&result[..result_len]).map_err(Error::from)? {
            trlib_core::api::AuthResponse::Authorized(_) => Ok(value),
            trlib_core::api::AuthResponse::RpcError(error) => {
                eprintln!(
                    "TRBotApi Test DC auth RPC error: code={} message={:?}",
                    error.code, error.message
                );
                Err(Error::new(ErrorKind::InvalidToken, 0, error.code as u32))
            }
            _ => Err(Error::new(ErrorKind::InvalidState, 0, 0)),
        }
    }

    fn call_raw(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let auth_key = AuthKeyRef::new(self.material.auth_key()).map_err(Error::from)?;
        let padding_len = {
            let aligned = (16usize - ((32 + body.len()) & 15)) & 15;
            if aligned < 12 { aligned + 16 } else { aligned }
        };
        let mut padding = [0u8; 64];
        self.random.fill(&mut padding[..padding_len])?;
        let mut packet = vec![0u8; body.len() + 1_200];
        let packet_len = encode_encrypted(
            &RustCrypto,
            CryptoDirection::ClientToServer,
            &auth_key,
            self.material.auth_key_id(),
            OutboundMessage {
                server_salt: self.material.server_salt(),
                session_id: self.session_id,
                message_id: message_id()?,
                sequence_number: self.sequence,
                body,
                padding: &padding[..padding_len],
            },
            &mut packet,
        )
        .map_err(Error::from)?;
        self.sequence = self.sequence.wrapping_add(1);
        let mut framed = vec![0u8; packet_len + 16];
        let framed_len = self
            .codec
            .encode(&packet[..packet_len], &mut framed)
            .map_err(Error::from)?;
        self.stream
            .write_all(&framed[..framed_len])
            .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 3))?;

        let mut frame = vec![0u8; MAX_FRAME];
        for _ in 0..16 {
            let frame_len = receive_frame(&mut self.stream, &self.codec, &mut frame)?;
            let payload = &mut frame[4..frame_len];
            let envelope =
                match parse_external(payload, (MAX_FRAME - 4) as u32).map_err(Error::from)? {
                    ExternalEnvelope::Encrypted(value) => value,
                    ExternalEnvelope::Plain(_) => {
                        return Err(Error::new(ErrorKind::Wire, 0, 0));
                    }
                };
            let message_key = *envelope.message_key;
            RustCrypto
                .open(
                    CryptoDirection::ServerToClient,
                    &auth_key,
                    &message_key,
                    &mut payload[24..],
                )
                .map_err(Error::from)?;
            let decrypted =
                parse_decrypted(&payload[24..], (MAX_FRAME - 4) as u32).map_err(Error::from)?;
            if let Ok(result) = rpc_result_body(decrypted.body) {
                if result.len() > output.len() {
                    return Err(Error::new(
                        ErrorKind::OutputTooSmall,
                        0,
                        result.len() as u32,
                    ));
                }
                output[..result.len()].copy_from_slice(result);
                return Ok(result.len());
            }
        }
        Err(Error::new(ErrorKind::InvalidState, 0, 0))
    }
}

impl BotTransport for TestDcTransport {
    fn call(&mut self, method: &[u8], output: &mut [u8]) -> Result<usize> {
        let mut result = vec![0u8; MAX_FRAME];
        let length = self.call_raw(method, &mut result)?;
        let response = &result[..length];
        let mut cursor = Cursor::new(method);
        let method_id = cursor.read_constructor().map_err(Error::from)?;
        if method_id != MESSAGES_SEND_MESSAGE {
            return Err(Error::new(ErrorKind::Unsupported, 0, method_id.get()));
        }
        let (message_id, date) = sent_message_values(response).unwrap_or((0, 0));
        let peer_id = method_peer_id(method).unwrap_or(self.bot_id);
        let mut writer = JsonWriter::new(output);
        writer.write(b"{\"message_id\":")?;
        writer.write_i64(i64::from(message_id))?;
        writer.write(b",\"date\":")?;
        writer.write_i64(i64::from(date))?;
        writer.write(b",\"chat\":{\"id\":")?;
        writer.write_i64(peer_id)?;
        writer.write(b",\"type\":\"private\"},\"text\":\"\"}")?;
        Ok(writer.position())
    }

    fn call_bot_api(&mut self, method: &str, _body: &[u8], output: &mut [u8]) -> Result<usize> {
        if method.eq_ignore_ascii_case("sendMessage") {
            return self.call_rich_send_message(_body, output);
        }
        if method.eq_ignore_ascii_case("sendPhoto")
            || method.eq_ignore_ascii_case("sendVideo")
            || method.eq_ignore_ascii_case("sendAnimation")
            || method.eq_ignore_ascii_case("sendAudio")
            || method.eq_ignore_ascii_case("sendDocument")
            || method.eq_ignore_ascii_case("sendVoice")
            || method.eq_ignore_ascii_case("sendVideoNote")
            || method.eq_ignore_ascii_case("sendSticker")
            || method.eq_ignore_ascii_case("sendLocation")
            || method.eq_ignore_ascii_case("sendVenue")
            || method.eq_ignore_ascii_case("sendContact")
            || method.eq_ignore_ascii_case("sendDice")
        {
            return self.call_media(method, _body, output);
        }
        if method.eq_ignore_ascii_case("sendPoll") {
            return self.call_poll(_body, output);
        }
        if method.eq_ignore_ascii_case("sendMediaGroup") {
            return self.call_media_group(_body, output);
        }
        if method.eq_ignore_ascii_case("answerInlineQuery") {
            return self.call_answer_inline_query(_body, output);
        }
        if method.eq_ignore_ascii_case("getStickerSet") {
            return self.call_get_sticker_set(_body, output);
        }
        if method.eq_ignore_ascii_case("getCustomEmojiStickers") {
            return self.call_get_custom_emoji_stickers(_body, output);
        }
        if method.eq_ignore_ascii_case("logOut") || method.eq_ignore_ascii_case("close") {
            return self.call_logout(output);
        }
        if method.eq_ignore_ascii_case("deleteMessage")
            || method.eq_ignore_ascii_case("deleteMessages")
        {
            return self.call_delete_messages(_body, output);
        }
        if method.eq_ignore_ascii_case("sendChatAction") {
            return self.call_chat_action(_body, output);
        }
        if method.eq_ignore_ascii_case("forwardMessage")
            || method.eq_ignore_ascii_case("copyMessage")
            || method.eq_ignore_ascii_case("forwardMessages")
            || method.eq_ignore_ascii_case("copyMessages")
        {
            return self.call_forward_messages(method, _body, output);
        }
        if method.eq_ignore_ascii_case("setMessageReaction") {
            return self.call_message_reaction(_body, output);
        }
        if method.eq_ignore_ascii_case("editMessageText") {
            return self.call_edit_message_text(_body, output);
        }
        if method.eq_ignore_ascii_case("setChatTitle") {
            return self.call_set_chat_title(_body, output);
        }
        if method.eq_ignore_ascii_case("setChatDescription") {
            return self.call_set_chat_description(_body, output);
        }
        if method.eq_ignore_ascii_case("pinChatMessage")
            || method.eq_ignore_ascii_case("unpinChatMessage")
        {
            return self.call_pin_message(method, _body, output);
        }
        if method.eq_ignore_ascii_case("unpinAllChatMessages") {
            return self.call_unpin_all(_body, output);
        }
        if method.eq_ignore_ascii_case("leaveChat") {
            return self.call_leave_chat(_body, output);
        }
        if method.eq_ignore_ascii_case("getChatMemberCount") {
            return self.call_chat_member_count(_body, output);
        }
        Err(Error::new(ErrorKind::Unsupported, 0, 0))
    }
}

impl TestDcTransport {
    fn call_rich_send_message(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let text = json_string(body, "text")?;
        let peer = core_peer(chat_id, self.bot_id)?;
        let reply_to = json_i64(body, "reply_to_message_id")
            .or_else(|_| json_i64(body, "message_id_to_reply"))
            .ok();
        let entities = json_array_field(body, "entities");
        let entity_count = entities.map(count_array_objects).unwrap_or(0);
        let inline_markup = json_object_field(body, "reply_markup")
            .and_then(|value| json_array_field(value, "inline_keyboard"));
        let has_inline_markup = inline_markup.is_some();
        let mut flags = 0u32;
        if json_bool(body, "disable_web_page_preview").unwrap_or(false) {
            flags |= 1 << 1;
        }
        if json_bool(body, "disable_notification").unwrap_or(false) {
            flags |= 1 << 5;
        }
        if json_bool(body, "protect_content").unwrap_or(false) {
            flags |= 1 << 14;
        }
        if reply_to.is_some() {
            flags |= 1;
        }
        if entity_count != 0 {
            flags |= 1 << 3;
        }
        if has_inline_markup {
            flags |= 1 << 2;
        }

        let mut request = [0u8; 64 * 1024];
        let mut writer = Writer::new(&mut request);
        writer
            .write_constructor(MESSAGES_SEND_MESSAGE)
            .map_err(Error::from)?;
        writer.write_i64(0).map_err(Error::from)?;
        writer.write_u32(flags).map_err(Error::from)?;
        peer.write(&mut writer).map_err(Error::from)?;
        if let Some(reply_to) = reply_to {
            writer
                .write_constructor(INPUT_REPLY_TO_MESSAGE)
                .map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            writer.write_i32(reply_to as i32).map_err(Error::from)?;
        }
        writer.write_string(text).map_err(Error::from)?;
        writer
            .write_i64(message_id()? as i64)
            .map_err(Error::from)?;
        if let Some(inline_markup) = inline_markup {
            write_inline_markup(&mut writer, inline_markup)?;
        }
        if entity_count != 0 {
            writer.write_constructor(VECTOR).map_err(Error::from)?;
            writer.write_i32(entity_count as i32).map_err(Error::from)?;
            write_entities(&mut writer, entities.unwrap_or(&[]), entity_count)?;
        }
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        let (message_id, date) = sent_message_values(&response[..length]).unwrap_or((0, 0));
        write_message_json(output, message_id, date, chat_id, text)
    }

    fn call_media(&mut self, method: &str, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let peer = core_peer(chat_id, self.bot_id)?;
        let reply_to = json_i64(body, "reply_to_message_id").ok();
        let caption = json_string(body, "caption").unwrap_or("");
        let entities = json_array_field(body, "caption_entities");
        let entity_count = entities.map(count_array_objects).unwrap_or(0);
        let mut flags = 0u32;
        if json_bool(body, "disable_notification").unwrap_or(false) {
            flags |= 1 << 5;
        }
        if json_bool(body, "protect_content").unwrap_or(false) {
            flags |= 1 << 14;
        }
        if reply_to.is_some() {
            flags |= 1;
        }
        if entity_count != 0 {
            flags |= 1 << 3;
        }

        let mut request = [0u8; 64 * 1024];
        let mut writer = Writer::new(&mut request);
        writer
            .write_constructor(MESSAGES_SEND_MEDIA)
            .map_err(Error::from)?;
        writer.write_u32(flags).map_err(Error::from)?;
        peer.write(&mut writer).map_err(Error::from)?;
        if let Some(reply_to) = reply_to {
            writer
                .write_constructor(INPUT_REPLY_TO_MESSAGE)
                .map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            writer.write_i32(reply_to as i32).map_err(Error::from)?;
        }
        write_input_media(&mut writer, method, body)?;
        writer.write_string(caption).map_err(Error::from)?;
        writer
            .write_i64(message_id()? as i64)
            .map_err(Error::from)?;
        if entity_count != 0 {
            writer.write_constructor(VECTOR).map_err(Error::from)?;
            writer.write_i32(entity_count as i32).map_err(Error::from)?;
            write_entities(&mut writer, entities.unwrap_or(&[]), entity_count)?;
        }
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        let (message_id, date) = sent_message_values(&response[..length]).unwrap_or((0, 0));
        write_message_json(output, message_id, date, chat_id, caption)
    }

    fn call_media_group(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let peer = core_peer(chat_id, self.bot_id)?;
        let media = json_array_field(body, "media")
            .ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
        let count = count_array_objects(media);
        if count == 0 || count > 10 {
            return Err(Error::new(ErrorKind::InvalidValue, 0, 10));
        }
        let reply_to = json_i64(body, "reply_to_message_id").ok();
        let mut request = [0u8; 64 * 1024];
        let mut writer = Writer::new(&mut request);
        writer
            .write_constructor(MESSAGES_SEND_MULTI_MEDIA)
            .map_err(Error::from)?;
        writer
            .write_u32(if reply_to.is_some() { 1 } else { 0 })
            .map_err(Error::from)?;
        peer.write(&mut writer).map_err(Error::from)?;
        if let Some(reply_to) = reply_to {
            writer
                .write_constructor(INPUT_REPLY_TO_MESSAGE)
                .map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            writer.write_i32(reply_to as i32).map_err(Error::from)?;
        }
        writer.write_constructor(VECTOR).map_err(Error::from)?;
        writer.write_i32(count as i32).map_err(Error::from)?;
        let mut cursor = JsonArrayCursor::new(media)?;
        while let Some(item) = cursor.next()? {
            let kind = json_string(item, "type")?;
            if !matches!(kind, "photo" | "video" | "audio" | "document") {
                return Err(Error::new(ErrorKind::Unsupported, 0, 0));
            }
            let source = json_string(item, "media")?;
            if !(source.starts_with("http://") || source.starts_with("https://")) {
                return Err(Error::new(ErrorKind::Unsupported, 0, 0));
            }
            writer
                .write_constructor(INPUT_SINGLE_MEDIA)
                .map_err(Error::from)?;
            let entities = json_array_field(item, "caption_entities");
            let entity_count = entities.map(count_array_objects).unwrap_or(0);
            writer
                .write_u32(if entity_count == 0 { 0 } else { 1 })
                .map_err(Error::from)?;
            if kind == "photo" {
                writer
                    .write_constructor(INPUT_MEDIA_PHOTO_EXTERNAL)
                    .map_err(Error::from)?;
                writer.write_u32(0).map_err(Error::from)?;
                writer.write_string(source).map_err(Error::from)?;
            } else {
                writer
                    .write_constructor(INPUT_MEDIA_DOCUMENT_EXTERNAL)
                    .map_err(Error::from)?;
                writer.write_u32(0).map_err(Error::from)?;
                writer.write_string(source).map_err(Error::from)?;
            }
            writer
                .write_i64(message_id()? as i64)
                .map_err(Error::from)?;
            writer
                .write_string(json_string(item, "caption").unwrap_or(""))
                .map_err(Error::from)?;
            if entity_count != 0 {
                writer.write_constructor(VECTOR).map_err(Error::from)?;
                writer.write_i32(entity_count as i32).map_err(Error::from)?;
                write_entities(&mut writer, entities.unwrap_or(&[]), entity_count)?;
            }
        }
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        let (message_id, date) = sent_message_values(&response[..length]).unwrap_or((0, 0));
        let mut json = JsonWriter::new(output);
        json.write(b"[{\"message_id\":")?;
        json.write_i64(i64::from(message_id))?;
        json.write(b",\"date\":")?;
        json.write_i64(i64::from(date))?;
        json.write(b",\"chat\":{\"id\":")?;
        json.write_i64(chat_id)?;
        json.write(b",\"type\":\"private\"}]")?;
        Ok(json.position())
    }

    fn call_poll(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let peer = core_peer(chat_id, self.bot_id)?;
        let question = json_string(body, "question")?;
        let options = json_array_field(body, "options")
            .ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
        let option_count = count_array_objects(options);
        if !(2..=10).contains(&option_count) {
            return Err(Error::new(ErrorKind::InvalidValue, 0, 10));
        }
        let reply_to = json_i64(body, "reply_to_message_id").ok();
        let mut flags = 0u32;
        if !json_bool(body, "is_anonymous").unwrap_or(true) {
            flags |= 1 << 1;
        }
        if json_bool(body, "allows_multiple_answers").unwrap_or(false) {
            flags |= 1 << 2;
        }
        if json_bool(body, "type").unwrap_or(false)
            || json_string(body, "type").ok() == Some("quiz")
        {
            flags |= 1 << 3;
        }
        let close_period = json_i64(body, "open_period").ok();
        let close_date = json_i64(body, "close_date").ok();
        if close_period.is_some() {
            flags |= 1 << 4;
        }
        if close_date.is_some() {
            flags |= 1 << 5;
        }

        let mut request = [0u8; 64 * 1024];
        let mut writer = Writer::new(&mut request);
        writer
            .write_constructor(MESSAGES_SEND_MEDIA)
            .map_err(Error::from)?;
        let mut send_flags = 0u32;
        if json_bool(body, "disable_notification").unwrap_or(false) {
            send_flags |= 1 << 5;
        }
        if json_bool(body, "protect_content").unwrap_or(false) {
            send_flags |= 1 << 14;
        }
        if reply_to.is_some() {
            send_flags |= 1;
        }
        let explanation_entities = json_array_field(body, "explanation_entities");
        let explanation_entity_count = explanation_entities.map(count_array_objects).unwrap_or(0);
        if explanation_entity_count != 0 {
            send_flags |= 1 << 3;
        }
        writer.write_u32(send_flags).map_err(Error::from)?;
        peer.write(&mut writer).map_err(Error::from)?;
        if let Some(reply_to) = reply_to {
            writer
                .write_constructor(INPUT_REPLY_TO_MESSAGE)
                .map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            writer.write_i32(reply_to as i32).map_err(Error::from)?;
        }
        writer
            .write_constructor(INPUT_MEDIA_POLL)
            .map_err(Error::from)?;
        writer.write_u32(0).map_err(Error::from)?;
        writer.write_constructor(POLL).map_err(Error::from)?;
        writer.write_i64(0).map_err(Error::from)?;
        writer.write_u32(flags).map_err(Error::from)?;
        write_text_with_entities(&mut writer, question)?;
        writer.write_constructor(VECTOR).map_err(Error::from)?;
        writer.write_i32(option_count as i32).map_err(Error::from)?;
        let mut option_cursor = JsonArrayCursor::new(options)?;
        let mut option_index = 0u8;
        while let Some(option) = option_cursor.next()? {
            let option = json_scalar_string(option)?;
            writer.write_constructor(POLL_ANSWER).map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            write_text_with_entities(&mut writer, option)?;
            writer.write_bytes(&[option_index]).map_err(Error::from)?;
            option_index = option_index.wrapping_add(1);
        }
        if let Some(close_period) = close_period {
            writer.write_i32(close_period as i32).map_err(Error::from)?;
        }
        if let Some(close_date) = close_date {
            writer.write_i32(close_date as i32).map_err(Error::from)?;
        }
        writer.write_i64(0).map_err(Error::from)?;
        writer
            .write_string(json_string(body, "explanation").unwrap_or(""))
            .map_err(Error::from)?;
        writer
            .write_i64(message_id()? as i64)
            .map_err(Error::from)?;
        if explanation_entity_count != 0 {
            writer.write_constructor(VECTOR).map_err(Error::from)?;
            writer
                .write_i32(explanation_entity_count as i32)
                .map_err(Error::from)?;
            write_entities(
                &mut writer,
                explanation_entities.unwrap_or(&[]),
                explanation_entity_count,
            )?;
        }
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        let (message_id, date) = sent_message_values(&response[..length]).unwrap_or((0, 0));
        write_message_json(output, message_id, date, chat_id, question)
    }

    fn call_answer_inline_query(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let query_id = json_i64(body, "inline_query_id")?;
        let results = json_array_field(body, "results")
            .ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
        let result_count = count_array_objects(results);
        if result_count > 50 {
            return Err(Error::new(ErrorKind::LimitExceeded, 0, 50));
        }
        let mut flags = 0u32;
        if json_bool(body, "is_personal").unwrap_or(false) {
            flags |= 1 << 1;
        }
        let next_offset = json_string(body, "next_offset").ok();
        if next_offset.is_some() {
            flags |= 1 << 2;
        }
        let mut request = [0u8; 64 * 1024];
        let mut writer = Writer::new(&mut request);
        writer
            .write_constructor(MESSAGES_SET_INLINE_BOT_RESULTS)
            .map_err(Error::from)?;
        writer.write_u32(flags).map_err(Error::from)?;
        writer.write_i64(query_id).map_err(Error::from)?;
        writer.write_constructor(VECTOR).map_err(Error::from)?;
        writer.write_i32(result_count as i32).map_err(Error::from)?;
        write_inline_results(&mut writer, results, result_count)?;
        writer
            .write_i32(json_i64(body, "cache_time").unwrap_or(300) as i32)
            .map_err(Error::from)?;
        if let Some(next_offset) = next_offset {
            writer.write_string(next_offset).map_err(Error::from)?;
        }
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        bool_result(&response[..length], output)
    }

    fn call_get_sticker_set(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let name = json_string(body, "name")?;
        let mut request = [0u8; 256];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_GET_STICKER_SET,
            &[
                schema::Value::Boxed(INPUT_STICKER_SET_SHORT_NAME, &[schema::Value::Str(name)]),
                schema::Value::Int(0),
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        // Keep the conversion bounded and explicit: the TL set has been
        // fetched successfully, while file-id/document conversion belongs to
        // the media cache.  Returning the set metadata avoids inventing
        // unusable file ids when no media cache is configured.
        let title = sticker_set_title(&response[..length]).unwrap_or("");
        let mut json = JsonWriter::new(output);
        json.write(b"{\"name\":")?;
        json.write_json_string(name)?;
        json.write(b",\"title\":")?;
        json.write_json_string(title)?;
        json.write(b",\"is_animated\":false,\"is_video\":false,\"stickers\":[]}")?;
        Ok(json.position())
    }

    fn call_get_custom_emoji_stickers(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let (ids, count) = json_long_ids(body, "sticker_ids")?;
        let mut request = [0u8; 2 * 1024];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_GET_CUSTOM_EMOJI_DOCUMENTS,
            &[schema::Value::Longs(&ids[..count])],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        // The actual file_id is produced by the embedding media cache.  Do
        // not fabricate one from a document id; an empty valid array is safer
        // than returning unusable identifiers.
        write_bytes(output, b"[]")
    }

    fn call_logout(&mut self, output: &mut [u8]) -> Result<usize> {
        let mut request = [0u8; 32];
        let mut writer = Writer::new(&mut request);
        write_log_out(&mut writer).map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        let mut cursor = Cursor::new(&response[..length]);
        let result = cursor.read_constructor().map_err(Error::from)?;
        match result {
            BOOL_TRUE => write_bytes(output, b"true"),
            BOOL_FALSE => write_bytes(output, b"false"),
            _ => Err(Error::new(ErrorKind::Wire, 0, result.get())),
        }
    }

    fn call_delete_messages(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let (ids, id_count) = if let Ok(values) = json_message_ids(body, "message_ids") {
            values
        } else {
            let mut values = [0i32; 100];
            values[0] = json_i64(body, "message_id")? as i32;
            (values, 1)
        };
        let mut request = [0u8; 2 * 1024];
        let mut writer = Writer::new(&mut request);
        write_delete_messages(&mut writer, &ids[..id_count], true).map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        write_bytes(output, b"true")
    }

    fn call_chat_action(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let action = json_string(body, "action")?;
        let peer = schema_peer(chat_id, self.bot_id)?;
        let action_id = match action {
            "typing" => SEND_MESSAGE_TYPING_ACTION,
            "upload_photo" => SEND_MESSAGE_UPLOAD_PHOTO_ACTION,
            "record_video" | "record_video_note" => SEND_MESSAGE_RECORD_VIDEO_ACTION,
            "upload_video" | "upload_video_note" => SEND_MESSAGE_UPLOAD_VIDEO_ACTION,
            "record_voice" => SEND_MESSAGE_RECORD_AUDIO_ACTION,
            "upload_voice" => SEND_MESSAGE_UPLOAD_AUDIO_ACTION,
            "upload_document" => SEND_MESSAGE_UPLOAD_DOCUMENT_ACTION,
            "choose_sticker" => SEND_MESSAGE_CHOOSE_STICKER_ACTION,
            "choose_contact" => SEND_MESSAGE_CHOOSE_CONTACT_ACTION,
            "find_location" => SEND_MESSAGE_GEO_LOCATION_ACTION,
            "cancel" => SEND_MESSAGE_CANCEL_ACTION,
            _ => return Err(Error::new(ErrorKind::InvalidValue, 0, 0)),
        };
        let mut request = [0u8; 256];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_SET_TYPING,
            &[
                schema::Value::Peer(peer),
                schema::Value::Skip,
                schema::Value::Empty(action_id),
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        bool_result(&response[..length], output)
    }

    fn call_message_reaction(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let message_id = json_i64(body, "message_id")? as i32;
        let reaction = json_string(body, "emoji").or_else(|_| json_string(body, "reaction"))?;
        let peer = schema_peer(chat_id, self.bot_id)?;
        let mut reaction_body = [0u8; 128];
        let mut reaction_writer = Writer::new(&mut reaction_body);
        reaction_writer.write_i32(1).map_err(Error::from)?;
        reaction_writer
            .write_constructor(REACTION_EMOJI)
            .map_err(Error::from)?;
        reaction_writer
            .write_string(reaction)
            .map_err(Error::from)?;
        let mut request = [0u8; 512];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_SEND_REACTION,
            &[
                schema::Value::False,
                schema::Value::False,
                schema::Value::Peer(peer),
                schema::Value::Int(message_id),
                schema::Value::Raw(VECTOR, reaction_writer.written()),
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        write_bytes(output, b"true")
    }

    fn call_forward_messages(
        &mut self,
        method: &str,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let from_chat_id = json_i64(body, "from_chat_id")?;
        let to_chat_id = json_i64(body, "chat_id")?;
        let (ids, id_count) = if let Ok(values) = json_message_ids(body, "message_ids") {
            values
        } else {
            let mut values = [0i32; 100];
            values[0] = json_i64(body, "message_id")? as i32;
            (values, 1)
        };
        let from_peer = schema_peer(from_chat_id, self.bot_id)?;
        let to_peer = schema_peer(to_chat_id, self.bot_id)?;
        let random_seed = message_id()? as i64;
        let mut random_ids = [0i64; 100];
        for (index, value) in random_ids.iter_mut().enumerate().take(id_count) {
            *value = random_seed.wrapping_add(index as i64);
        }
        let drop_author = method.eq_ignore_ascii_case("copyMessage")
            || method.eq_ignore_ascii_case("copyMessages");
        let mut request = [0u8; 2048];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_FORWARD_MESSAGES,
            &[
                schema::Value::False,
                schema::Value::False,
                schema::Value::False,
                if drop_author {
                    schema::Value::True
                } else {
                    schema::Value::False
                },
                schema::Value::False,
                schema::Value::False,
                schema::Value::False,
                schema::Value::Peer(from_peer),
                schema::Value::Ints(&ids[..id_count]),
                schema::Value::Longs(&random_ids[..id_count]),
                schema::Value::Peer(to_peer),
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
                schema::Value::Skip,
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        let mut json = JsonWriter::new(output);
        json.write(b"{\"message_id\":")?;
        json.write_i64(i64::from(ids[0]))?;
        json.write(b",\"date\":0,\"chat\":{\"id\":")?;
        json.write_i64(to_chat_id)?;
        json.write(b",\"type\":\"private\"}")?;
        json.write(b"}")?;
        Ok(json.position())
    }

    fn call_edit_message_text(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let message_id = json_i64(body, "message_id")? as i32;
        let text = json_string(body, "text")?;
        let peer = core_peer(chat_id, self.bot_id)?;
        let mut request = [0u8; 8 * 1024];
        let mut writer = Writer::new(&mut request);
        let entities = json_array_field(body, "entities");
        let entity_count = entities.map(count_array_objects).unwrap_or(0);
        if entity_count == 0 {
            write_edit_message_text(&mut writer, peer, message_id, text, false, false)
                .map_err(Error::from)?;
        } else {
            writer
                .write_constructor(MESSAGES_EDIT_MESSAGE)
                .map_err(Error::from)?;
            writer.write_u32(1 << 3 | 1 << 11).map_err(Error::from)?;
            peer.write(&mut writer).map_err(Error::from)?;
            writer.write_i32(message_id).map_err(Error::from)?;
            writer.write_string(text).map_err(Error::from)?;
            writer.write_constructor(VECTOR).map_err(Error::from)?;
            writer.write_i32(entity_count as i32).map_err(Error::from)?;
            write_entities(&mut writer, entities.unwrap_or(&[]), entity_count)?;
        }
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        let mut json = JsonWriter::new(output);
        json.write(b"{\"message_id\":")?;
        json.write_i64(i64::from(message_id))?;
        json.write(b",\"date\":0,\"chat\":{\"id\":")?;
        json.write_i64(chat_id)?;
        json.write(b",\"type\":\"private\"},\"text\":")?;
        json.write_json_string(text)?;
        json.write(b"}")?;
        Ok(json.position())
    }

    fn call_set_chat_title(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let title = json_string(body, "title")?;
        if chat_id >= 0 || chat_id < -1_000_000_000_000 {
            return Err(Error::new(ErrorKind::Unsupported, 0, 0));
        }
        let mut request = [0u8; 512];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_EDIT_CHAT_TITLE,
            &[schema::Value::Long(chat_id), schema::Value::Str(title)],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        write_bytes(output, b"true")
    }

    fn call_set_chat_description(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let about = json_string(body, "description")?;
        let peer = schema_peer(chat_id, self.bot_id)?;
        let mut request = [0u8; 512];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_EDIT_CHAT_ABOUT,
            &[schema::Value::Peer(peer), schema::Value::Str(about)],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        bool_result(&response[..length], output)
    }

    fn call_pin_message(&mut self, method: &str, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        let message_id = json_i64(body, "message_id")? as i32;
        let peer = schema_peer(chat_id, self.bot_id)?;
        let unpin = method.eq_ignore_ascii_case("unpinChatMessage");
        let silent = json_bool(body, "disable_notification").unwrap_or(false);
        let mut request = [0u8; 256];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_UPDATE_PINNED_MESSAGE,
            &[
                if silent {
                    schema::Value::True
                } else {
                    schema::Value::False
                },
                if unpin {
                    schema::Value::True
                } else {
                    schema::Value::False
                },
                schema::Value::False,
                schema::Value::Peer(peer),
                schema::Value::Int(message_id),
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        write_bytes(output, b"true")
    }

    fn call_unpin_all(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let peer = schema_peer(json_i64(body, "chat_id")?, self.bot_id)?;
        let mut request = [0u8; 128];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_UNPIN_ALL_MESSAGES,
            &[
                schema::Value::Peer(peer),
                schema::Value::Skip,
                schema::Value::Skip,
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        write_bytes(output, b"true")
    }

    fn call_leave_chat(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        if chat_id >= 0 || chat_id < -1_000_000_000_000 {
            return Err(Error::new(ErrorKind::Unsupported, 0, 0));
        }
        let mut request = [0u8; 128];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_DELETE_CHAT_USER,
            &[
                schema::Value::False,
                schema::Value::Long(-chat_id),
                schema::Value::Empty(INPUT_USER_SELF),
            ],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        self.call_raw(writer.written(), &mut response)?;
        write_bytes(output, b"true")
    }

    fn call_chat_member_count(&mut self, body: &[u8], output: &mut [u8]) -> Result<usize> {
        let chat_id = json_i64(body, "chat_id")?;
        if chat_id >= 0 || chat_id < -1_000_000_000_000 {
            return Err(Error::new(ErrorKind::Unsupported, 0, 0));
        }
        let mut request = [0u8; 64];
        let mut writer = Writer::new(&mut request);
        schema::serialize(
            &mut writer,
            MESSAGES_GET_FULL_CHAT,
            &[schema::Value::Long(-chat_id)],
        )
        .map_err(Error::from)?;
        let mut response = [0u8; MAX_FRAME];
        let length = self.call_raw(writer.written(), &mut response)?;
        let count = chat_participant_count(&response[..length])?;
        let mut json = JsonWriter::new(output);
        json.write_i64(i64::from(count))?;
        Ok(json.position())
    }
}

fn write_text_with_entities(writer: &mut Writer<'_>, text: &str) -> Result<()> {
    writer
        .write_constructor(TEXT_WITH_ENTITIES)
        .map_err(Error::from)?;
    writer.write_string(text).map_err(Error::from)?;
    writer.write_constructor(VECTOR).map_err(Error::from)?;
    writer.write_i32(0).map_err(Error::from)
}

fn write_input_media(writer: &mut Writer<'_>, method: &str, body: &[u8]) -> Result<()> {
    if method.eq_ignore_ascii_case("sendLocation") {
        let latitude = json_f64(body, "latitude")?;
        let longitude = json_f64(body, "longitude")?;
        writer
            .write_constructor(INPUT_MEDIA_GEO_POINT)
            .map_err(Error::from)?;
        writer
            .write_constructor(INPUT_GEO_POINT)
            .map_err(Error::from)?;
        writer.write_u32(0).map_err(Error::from)?;
        writer.write_u64(latitude.to_bits()).map_err(Error::from)?;
        writer.write_u64(longitude.to_bits()).map_err(Error::from)
    } else if method.eq_ignore_ascii_case("sendVenue") {
        let latitude = json_f64(body, "latitude")?;
        let longitude = json_f64(body, "longitude")?;
        writer
            .write_constructor(trlib_core::generated::INPUT_MEDIA_VENUE)
            .map_err(Error::from)?;
        writer
            .write_constructor(INPUT_GEO_POINT)
            .map_err(Error::from)?;
        writer.write_u32(0).map_err(Error::from)?;
        writer.write_u64(latitude.to_bits()).map_err(Error::from)?;
        writer.write_u64(longitude.to_bits()).map_err(Error::from)?;
        writer
            .write_string(json_string(body, "title")?)
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "address")?)
            .map_err(Error::from)?;
        writer.write_string("foursquare").map_err(Error::from)?;
        writer
            .write_string(json_string(body, "foursquare_id").unwrap_or(""))
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "foursquare_type").unwrap_or(""))
            .map_err(Error::from)
    } else if method.eq_ignore_ascii_case("sendContact") {
        writer
            .write_constructor(INPUT_MEDIA_CONTACT)
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "phone_number")?)
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "first_name")?)
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "last_name").unwrap_or(""))
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "vcard").unwrap_or(""))
            .map_err(Error::from)
    } else if method.eq_ignore_ascii_case("sendDice") {
        writer
            .write_constructor(INPUT_MEDIA_DICE)
            .map_err(Error::from)?;
        writer
            .write_string(json_string(body, "emoji").unwrap_or("🎲"))
            .map_err(Error::from)
    } else {
        let key = if method.eq_ignore_ascii_case("sendPhoto") {
            "photo"
        } else if method.eq_ignore_ascii_case("sendVideo") {
            "video"
        } else if method.eq_ignore_ascii_case("sendAnimation") {
            "animation"
        } else if method.eq_ignore_ascii_case("sendAudio") {
            "audio"
        } else if method.eq_ignore_ascii_case("sendDocument") {
            "document"
        } else if method.eq_ignore_ascii_case("sendVoice") {
            "voice"
        } else if method.eq_ignore_ascii_case("sendVideoNote") {
            "video_note"
        } else {
            "sticker"
        };
        let source = json_string(body, key)?;
        if !(source.starts_with("http://") || source.starts_with("https://")) {
            return Err(Error::new(ErrorKind::Unsupported, 0, 0));
        }
        if method.eq_ignore_ascii_case("sendPhoto") {
            writer
                .write_constructor(INPUT_MEDIA_PHOTO_EXTERNAL)
                .map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            writer.write_string(source).map_err(Error::from)
        } else {
            writer
                .write_constructor(INPUT_MEDIA_DOCUMENT_EXTERNAL)
                .map_err(Error::from)?;
            writer.write_u32(0).map_err(Error::from)?;
            writer.write_string(source).map_err(Error::from)
        }
    }
}

fn write_entities(writer: &mut Writer<'_>, array: &[u8], expected: usize) -> Result<()> {
    let mut cursor = JsonArrayCursor::new(array)?;
    let mut count = 0usize;
    while let Some(object) = cursor.next()? {
        if count == expected {
            return Err(Error::new(ErrorKind::InvalidValue, 0, expected as u32));
        }
        write_entity(writer, object)?;
        count += 1;
    }
    if count != expected {
        return Err(Error::new(ErrorKind::InvalidValue, 0, count as u32));
    }
    Ok(())
}

fn write_entity(writer: &mut Writer<'_>, object: &[u8]) -> Result<()> {
    let kind = json_string(object, "type")?;
    let offset = json_i64(object, "offset")? as i32;
    let length = json_i64(object, "length")? as i32;
    let constructor = if kind == "mention" {
        MESSAGE_ENTITY_MENTION
    } else if kind == "hashtag" {
        MESSAGE_ENTITY_HASHTAG
    } else if kind == "cashtag" {
        MESSAGE_ENTITY_CASHTAG
    } else if kind == "bot_command" {
        MESSAGE_ENTITY_BOT_COMMAND
    } else if kind == "url" {
        MESSAGE_ENTITY_URL
    } else if kind == "email" {
        MESSAGE_ENTITY_EMAIL
    } else if kind == "phone_number" {
        MESSAGE_ENTITY_PHONE
    } else if kind == "bold" {
        MESSAGE_ENTITY_BOLD
    } else if kind == "italic" {
        MESSAGE_ENTITY_ITALIC
    } else if kind == "underline" {
        MESSAGE_ENTITY_UNDERLINE
    } else if kind == "strikethrough" {
        MESSAGE_ENTITY_STRIKE
    } else if kind == "spoiler" {
        MESSAGE_ENTITY_SPOILER
    } else if kind == "code" {
        MESSAGE_ENTITY_CODE
    } else if kind == "pre" {
        MESSAGE_ENTITY_PRE
    } else if kind == "text_link" {
        MESSAGE_ENTITY_TEXT_URL
    } else if kind == "text_mention" {
        MESSAGE_ENTITY_MENTION_NAME
    } else if kind == "custom_emoji" {
        MESSAGE_ENTITY_CUSTOM_EMOJI
    } else if kind == "blockquote" {
        MESSAGE_ENTITY_BLOCKQUOTE
    } else {
        return Err(Error::new(ErrorKind::Unsupported, 0, 0));
    };
    writer.write_constructor(constructor).map_err(Error::from)?;
    if kind == "blockquote" {
        writer.write_u32(0).map_err(Error::from)?;
    }
    writer.write_i32(offset).map_err(Error::from)?;
    writer.write_i32(length).map_err(Error::from)?;
    match kind {
        "pre" => writer
            .write_string(json_string(object, "language").unwrap_or(""))
            .map_err(Error::from),
        "text_link" => writer
            .write_string(json_string(object, "url")?)
            .map_err(Error::from),
        "text_mention" => writer
            .write_i64(json_i64(object, "user_id").or_else(|_| json_i64(object, "id"))?)
            .map_err(Error::from),
        "custom_emoji" => writer
            .write_i64(json_i64(object, "custom_emoji_id")?)
            .map_err(Error::from),
        _ => Ok(()),
    }
}

fn write_inline_results(writer: &mut Writer<'_>, array: &[u8], expected: usize) -> Result<()> {
    let mut cursor = JsonArrayCursor::new(array)?;
    let mut count = 0usize;
    while let Some(object) = cursor.next()? {
        if count == expected {
            return Err(Error::new(ErrorKind::InvalidValue, 0, expected as u32));
        }
        let kind = json_string(object, "type")?;
        if kind != "article" {
            return Err(Error::new(ErrorKind::Unsupported, 0, 0));
        }
        let id = json_string(object, "id")?;
        let message = json_string(object, "message_text")?;
        let title = json_string(object, "title").ok();
        let description = json_string(object, "description").ok();
        let url = json_string(object, "url").ok();
        let mut flags = 0u32;
        if title.is_some() {
            flags |= 1 << 1;
        }
        if description.is_some() {
            flags |= 1 << 2;
        }
        if url.is_some() {
            flags |= 1 << 3;
        }
        writer
            .write_constructor(INPUT_BOT_INLINE_RESULT)
            .map_err(Error::from)?;
        writer.write_u32(flags).map_err(Error::from)?;
        writer.write_string(id).map_err(Error::from)?;
        writer.write_string(kind).map_err(Error::from)?;
        if let Some(title) = title {
            writer.write_string(title).map_err(Error::from)?;
        }
        if let Some(description) = description {
            writer.write_string(description).map_err(Error::from)?;
        }
        if let Some(url) = url {
            writer.write_string(url).map_err(Error::from)?;
        }
        let entities = json_array_field(object, "entities");
        let entity_count = entities.map(count_array_objects).unwrap_or(0);
        writer
            .write_constructor(INPUT_BOT_INLINE_MESSAGE_TEXT)
            .map_err(Error::from)?;
        writer
            .write_u32(if entity_count == 0 { 0 } else { 1 << 1 })
            .map_err(Error::from)?;
        writer.write_string(message).map_err(Error::from)?;
        if entity_count != 0 {
            writer.write_constructor(VECTOR).map_err(Error::from)?;
            writer.write_i32(entity_count as i32).map_err(Error::from)?;
            write_entities(&mut *writer, entities.unwrap_or(&[]), entity_count)?;
        }
        count += 1;
    }
    if count != expected {
        return Err(Error::new(ErrorKind::InvalidValue, 0, count as u32));
    }
    Ok(())
}

fn write_message_json(
    output: &mut [u8],
    message_id: i32,
    date: i32,
    chat_id: i64,
    text: &str,
) -> Result<usize> {
    let mut json = JsonWriter::new(output);
    json.write(b"{\"message_id\":")?;
    json.write_i64(i64::from(message_id))?;
    json.write(b",\"date\":")?;
    json.write_i64(i64::from(date))?;
    json.write(b",\"chat\":{\"id\":")?;
    json.write_i64(chat_id)?;
    json.write(b",\"type\":\"private\"},\"text\":")?;
    json.write_json_string(text)?;
    json.write(b"}")?;
    Ok(json.position())
}

fn write_bytes(output: &mut [u8], value: &[u8]) -> Result<usize> {
    if value.len() > output.len() {
        return Err(Error::new(ErrorKind::OutputTooSmall, 0, value.len() as u32));
    }
    output[..value.len()].copy_from_slice(value);
    Ok(value.len())
}

fn bool_result(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut cursor = Cursor::new(input);
    match cursor.read_constructor().map_err(Error::from)? {
        BOOL_TRUE => write_bytes(output, b"true"),
        BOOL_FALSE => write_bytes(output, b"false"),
        id => Err(Error::new(ErrorKind::Wire, 0, id.get())),
    }
}

fn sticker_set_title(input: &[u8]) -> Option<&str> {
    let mut cursor = Cursor::new(input);
    if cursor.read_constructor().ok()? != MESSAGES_STICKER_SET {
        return None;
    }
    if cursor.read_constructor().ok()? != STICKER_SET {
        return None;
    }
    let flags = cursor.read_u32().ok()?;
    if flags & 1 != 0 {
        cursor.read_i32().ok()?;
    }
    cursor.read_i64().ok()?;
    cursor.read_i64().ok()?;
    cursor.read_string().ok().map(|value| value.as_str())
}

fn chat_participant_count(input: &[u8]) -> Result<i32> {
    let mut cursor = Cursor::new(input);
    if cursor.read_constructor().map_err(Error::from)? != MESSAGES_CHAT_FULL {
        return Err(Error::new(ErrorKind::Wire, 0, 0));
    }
    if cursor.read_constructor().map_err(Error::from)? != CHAT_FULL {
        return Err(Error::new(ErrorKind::Wire, 0, 0));
    }
    cursor.read_u32().map_err(Error::from)?;
    cursor.read_i64().map_err(Error::from)?;
    cursor.read_string().map_err(Error::from)?;
    match cursor.read_constructor().map_err(Error::from)? {
        CHAT_PARTICIPANTS => {
            cursor.read_i64().map_err(Error::from)?;
            if cursor.read_constructor().map_err(Error::from)? != VECTOR {
                return Err(Error::new(ErrorKind::Wire, 0, 0));
            }
            let count = cursor.read_u32().map_err(Error::from)?;
            if count > i32::MAX as u32 {
                return Err(Error::new(ErrorKind::InvalidValue, 0, count));
            }
            Ok(count as i32)
        }
        CHAT_PARTICIPANTS_FORBIDDEN => Ok(0),
        _ => Err(Error::new(ErrorKind::Wire, 0, 0)),
    }
}

fn core_peer(chat_id: i64, bot_id: i64) -> Result<trlib_core::api::InputPeer> {
    input_peer_for_chat(chat_id, Some(bot_id), None)
}

fn schema_peer(chat_id: i64, bot_id: i64) -> Result<schema::Peer> {
    match core_peer(chat_id, bot_id)? {
        trlib_core::api::InputPeer::SelfPeer => Ok(schema::Peer::Self_),
        trlib_core::api::InputPeer::Chat { chat_id } => Ok(schema::Peer::Chat { chat_id }),
        trlib_core::api::InputPeer::User { .. } | trlib_core::api::InputPeer::Channel { .. } => {
            Err(Error::new(ErrorKind::Unsupported, 0, 0))
        }
    }
}

fn json_field<'a>(input: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let key = key.as_bytes();
    let width = key.len().checked_add(2)?;
    let marker = input.windows(width).position(|window| {
        window.first() == Some(&b'"')
            && window.last() == Some(&b'"')
            && &window[1..width - 1] == key
    })?;
    let mut position = marker + width;
    while matches!(input.get(position), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        position += 1;
    }
    if input.get(position) != Some(&b':') {
        return None;
    }
    position += 1;
    while matches!(input.get(position), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        position += 1;
    }
    Some(&input[position..])
}

fn json_i64(input: &[u8], key: &str) -> Result<i64> {
    let value = json_field(input, key).ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
    let value = if value.first() == Some(&b'"') {
        let end = value[1..]
            .iter()
            .position(|byte| *byte == b'"')
            .ok_or_else(|| Error::new(ErrorKind::InvalidJson, 0, 0))?
            + 1;
        &value[1..end]
    } else {
        let end = value
            .iter()
            .position(|byte| matches!(*byte, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t'))
            .unwrap_or(value.len());
        &value[..end]
    };
    core::str::from_utf8(value)
        .map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))?
        .parse::<i64>()
        .map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))
}

fn json_string<'a>(input: &'a [u8], key: &str) -> Result<&'a str> {
    let value = json_field(input, key).ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
    if value.first() != Some(&b'"') {
        return Err(Error::new(ErrorKind::InvalidValue, 0, 0));
    }
    let end = value[1..]
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or_else(|| Error::new(ErrorKind::InvalidJson, 0, 0))?
        + 1;
    if value[1..end].contains(&b'\\') {
        return Err(Error::new(ErrorKind::Unsupported, 0, 0));
    }
    core::str::from_utf8(&value[1..end]).map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))
}

fn json_bool(input: &[u8], key: &str) -> Option<bool> {
    let value = json_field(input, key)?;
    if value.starts_with(b"true") {
        Some(true)
    } else if value.starts_with(b"false") {
        Some(false)
    } else {
        None
    }
}

fn json_message_ids(input: &[u8], key: &str) -> Result<([i32; 100], usize)> {
    let value = json_field(input, key).ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
    if value.first() != Some(&b'[') {
        return Err(Error::new(ErrorKind::InvalidValue, 0, 0));
    }
    let mut ids = [0i32; 100];
    let mut count = 0usize;
    let mut position = 1usize;
    loop {
        while matches!(
            value.get(position),
            Some(b' ' | b'\n' | b'\r' | b'\t' | b',')
        ) {
            position += 1;
        }
        if value.get(position) == Some(&b']') {
            break;
        }
        if count == ids.len() {
            return Err(Error::new(ErrorKind::LimitExceeded, 0, 100));
        }
        let start = position;
        while matches!(value.get(position), Some(b'-' | b'0'..=b'9')) {
            position += 1;
        }
        let number = core::str::from_utf8(&value[start..position])
            .map_err(|_| Error::new(ErrorKind::InvalidValue, start, 0))?
            .parse::<i32>()
            .map_err(|_| Error::new(ErrorKind::InvalidValue, start, 0))?;
        ids[count] = number;
        count += 1;
    }
    if count == 0 {
        return Err(Error::new(ErrorKind::InvalidValue, 0, 0));
    }
    Ok((ids, count))
}

fn json_long_ids(input: &[u8], key: &str) -> Result<([i64; 100], usize)> {
    let array =
        json_array_field(input, key).ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
    let mut values = [0i64; 100];
    let mut count = 0usize;
    let mut cursor = JsonArrayCursor::new(array)?;
    while let Some(value) = cursor.next()? {
        if count == values.len() {
            return Err(Error::new(ErrorKind::LimitExceeded, 0, 100));
        }
        let text =
            core::str::from_utf8(value).map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))?;
        let text = text.trim();
        let text = text
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(text);
        values[count] = text
            .parse::<i64>()
            .map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))?;
        count += 1;
    }
    if count == 0 {
        return Err(Error::new(ErrorKind::InvalidValue, 0, 0));
    }
    Ok((values, count))
}

fn json_f64(input: &[u8], key: &str) -> Result<f64> {
    let value = json_field(input, key).ok_or_else(|| Error::new(ErrorKind::MissingField, 0, 0))?;
    let end = value
        .iter()
        .position(|byte| matches!(*byte, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t'))
        .unwrap_or(value.len());
    core::str::from_utf8(&value[..end])
        .map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))?
        .parse::<f64>()
        .map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))
}

fn json_scalar_string(value: &[u8]) -> Result<&str> {
    let value = core::str::from_utf8(value)
        .map_err(|_| Error::new(ErrorKind::InvalidValue, 0, 0))?
        .trim();
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(Error::new(ErrorKind::InvalidValue, 0, 0));
    }
    let value = &value[1..value.len() - 1];
    if value.as_bytes().contains(&b'\\') {
        return Err(Error::new(ErrorKind::Unsupported, 0, 0));
    }
    Ok(value)
}

fn json_array_field<'a>(input: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let value = json_field(input, key)?;
    if value.first() != Some(&b'[') {
        return None;
    }
    let end = json_value_end(value, 0).ok()?;
    Some(&value[..end])
}

fn json_object_field<'a>(input: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let value = json_field(input, key)?;
    if value.first() != Some(&b'{') {
        return None;
    }
    let end = json_value_end(value, 0).ok()?;
    Some(&value[..end])
}

fn write_inline_markup(writer: &mut Writer<'_>, rows: &[u8]) -> Result<()> {
    let mut row_cursor = JsonArrayCursor::new(rows)?;
    let mut row_count = 0usize;
    while row_cursor.next()?.is_some() {
        row_count += 1;
    }
    let mut row_cursor = JsonArrayCursor::new(rows)?;
    writer
        .write_constructor(REPLY_INLINE_MARKUP)
        .map_err(Error::from)?;
    writer.write_constructor(VECTOR).map_err(Error::from)?;
    writer.write_i32(row_count as i32).map_err(Error::from)?;
    while let Some(row) = row_cursor.next()? {
        writer
            .write_constructor(KEYBOARD_BUTTON_ROW)
            .map_err(Error::from)?;
        let mut button_cursor = JsonArrayCursor::new(row)?;
        let mut button_count = 0usize;
        while button_cursor.next()?.is_some() {
            button_count += 1;
        }
        writer.write_constructor(VECTOR).map_err(Error::from)?;
        writer.write_i32(button_count as i32).map_err(Error::from)?;
        let mut button_cursor = JsonArrayCursor::new(row)?;
        while let Some(button) = button_cursor.next()? {
            let text = json_string(button, "text")?;
            if let Ok(data) = json_string(button, "callback_data") {
                writer
                    .write_constructor(KEYBOARD_BUTTON_CALLBACK)
                    .map_err(Error::from)?;
                writer.write_u32(0).map_err(Error::from)?;
                writer.write_string(text).map_err(Error::from)?;
                writer.write_bytes(data.as_bytes()).map_err(Error::from)?;
            } else if let Ok(url) = json_string(button, "url") {
                writer
                    .write_constructor(KEYBOARD_BUTTON_URL)
                    .map_err(Error::from)?;
                writer.write_u32(0).map_err(Error::from)?;
                writer.write_string(text).map_err(Error::from)?;
                writer.write_string(url).map_err(Error::from)?;
            } else {
                return Err(Error::new(ErrorKind::Unsupported, 0, 0));
            }
        }
    }
    Ok(())
}

fn count_array_objects(array: &[u8]) -> usize {
    let mut cursor = match JsonArrayCursor::new(array) {
        Ok(cursor) => cursor,
        Err(_) => return 0,
    };
    let mut count = 0usize;
    while let Ok(Some(_)) = cursor.next() {
        count = count.saturating_add(1);
    }
    count
}

struct JsonArrayCursor<'a> {
    input: &'a [u8],
    position: usize,
    done: bool,
}

impl<'a> JsonArrayCursor<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        if input.first() != Some(&b'[') {
            return Err(Error::new(ErrorKind::InvalidValue, 0, 0));
        }
        Ok(Self {
            input,
            position: 1,
            done: false,
        })
    }

    fn next(&mut self) -> Result<Option<&'a [u8]>> {
        if self.done {
            return Ok(None);
        }
        while matches!(
            self.input.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t' | b',')
        ) {
            self.position += 1;
        }
        if self.input.get(self.position) == Some(&b']') {
            self.done = true;
            return Ok(None);
        }
        let start = self.position;
        let end = json_value_end(self.input, start)?;
        self.position = end;
        Ok(Some(&self.input[start..end]))
    }
}

fn json_value_end(input: &[u8], start: usize) -> Result<usize> {
    let mut position = start;
    while matches!(input.get(position), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        position += 1;
    }
    let first = *input
        .get(position)
        .ok_or_else(|| Error::new(ErrorKind::InvalidJson, position, 0))?;
    if first == b'"' {
        position += 1;
        while let Some(byte) = input.get(position).copied() {
            position += 1;
            if byte == b'\\' {
                position += 1;
            } else if byte == b'"' {
                return Ok(position);
            }
        }
        return Err(Error::new(ErrorKind::InvalidJson, position, 0));
    }
    if first != b'[' && first != b'{' {
        while let Some(byte) = input.get(position).copied() {
            if matches!(byte, b',' | b']' | b'}') {
                break;
            }
            position += 1;
        }
        return Ok(position);
    }
    let open = first;
    let close = if open == b'[' { b']' } else { b'}' };
    let mut depth = 0usize;
    let mut string = false;
    while let Some(byte) = input.get(position).copied() {
        position += 1;
        if string {
            if byte == b'\\' {
                position += 1;
            } else if byte == b'"' {
                string = false;
            }
            continue;
        }
        match byte {
            b'"' => string = true,
            value if value == open => depth += 1,
            value if value == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(position);
                }
            }
            _ => {}
        }
    }
    Err(Error::new(ErrorKind::InvalidJson, position, 0))
}

fn sent_message_values(input: &[u8]) -> Option<(i32, i32)> {
    let mut cursor = Cursor::new(input);
    let id = cursor.read_constructor().ok()?;
    match id {
        UPDATE_SHORT_SENT_MESSAGE => {
            let flags = cursor.read_u32().ok()?;
            let message_id = if flags & (1 << 1) != 0 {
                cursor.read_i32().ok()?
            } else {
                0
            };
            let _pts = cursor.read_i32().ok()?;
            let _pts_count = cursor.read_i32().ok()?;
            let date = cursor.read_i32().ok()?;
            Some((message_id, date))
        }
        UPDATE_MESSAGE_ID => Some((cursor.read_i32().ok()?, 0)),
        UPDATES | UPDATES_COMBINED => {
            let vector = cursor.read_constructor().ok()?;
            if vector != VECTOR {
                return None;
            }
            let count = cursor.read_u32().ok()?;
            if count > 128 {
                return None;
            }
            for _ in 0..count {
                let start = cursor.position();
                let length = cursor.remaining_len();
                let update_id = cursor.read_constructor().ok()?;
                cursor = Cursor::new(&input[start..start + length]);
                if update_id == UPDATE_MESSAGE_ID {
                    cursor.read_constructor().ok()?;
                    return Some((cursor.read_i32().ok()?, 0));
                }
                return None;
            }
            None
        }
        _ => None,
    }
}

fn method_peer_id(input: &[u8]) -> Option<i64> {
    let mut cursor = Cursor::new(input);
    cursor.read_constructor().ok()?;
    cursor.read_i64().ok()?;
    let _flags = cursor.read_u32().ok()?;
    let peer = cursor.read_constructor().ok()?;
    match peer {
        INPUT_PEER_SELF => Some(0),
        INPUT_PEER_USER => Some(cursor.read_i64().ok()?),
        INPUT_PEER_CHAT => Some(-cursor.read_i64().ok()?),
        INPUT_PEER_CHANNEL => Some(-1_000_000_000_000 - cursor.read_i64().ok()?),
        _ => None,
    }
}

fn send_plain(stream: &mut TcpStream, codec: &Intermediate, body: &[u8]) -> Result<()> {
    let mut packet = vec![0u8; body.len() + 24];
    let mut writer = Writer::new(&mut packet);
    writer.write_u64(0).map_err(Error::from)?;
    writer.write_u64(message_id()?).map_err(Error::from)?;
    writer.write_u32(body.len() as u32).map_err(Error::from)?;
    writer.write_all(body).map_err(Error::from)?;
    let mut framed = vec![0u8; body.len() + 1_240];
    let framed_len = codec
        .encode(writer.written(), &mut framed)
        .map_err(Error::from)?;
    stream
        .write_all(&framed[..framed_len])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 4))
}

fn receive_frame(stream: &mut TcpStream, codec: &Intermediate, frame: &mut [u8]) -> Result<usize> {
    stream
        .read_exact(&mut frame[..4])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 5))?;
    let encoded = u32::from_le_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 6))?,
    );
    let total = encoded as usize + 4;
    if encoded == 0 || encoded & 3 != 0 || total > frame.len() {
        return Err(Error::new(ErrorKind::InvalidState, 0, encoded));
    }
    stream
        .read_exact(&mut frame[4..total])
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 7))?;
    codec
        .decode(&frame[..total], frame.len() as u32)
        .map_err(Error::from)?;
    Ok(total)
}

fn plain_body(frame: &[u8]) -> Result<&[u8]> {
    match parse_external(&frame[4..], 8_192).map_err(Error::from)? {
        ExternalEnvelope::Plain(value) => Ok(value.body),
        ExternalEnvelope::Encrypted(_) => Err(Error::new(ErrorKind::Wire, 0, 0)),
    }
}

fn random_u64(random: &mut dyn RandomSource) -> Result<u64> {
    let mut bytes = [0u8; 8];
    random.fill(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn message_id() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::InvalidState, 0, 8))?;
    Ok(((now.as_secs() << 32) | ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000)) & !3)
}

struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> trlib_core::Result<()> {
        let mut file = File::open("/dev/urandom")
            .map_err(|_| trlib_core::Error::new(trlib_core::ErrorKind::InvalidState, 0, 0))?;
        file.read_exact(bytes)
            .map_err(|_| trlib_core::Error::new(trlib_core::ErrorKind::InvalidState, 0, 0))
    }
}

struct JsonWriter<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> JsonWriter<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.position + bytes.len();
        if end > self.output.len() {
            return Err(Error::new(ErrorKind::OutputTooSmall, self.position, 0));
        }
        self.output[self.position..end].copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn write_i64(&mut self, value: i64) -> Result<()> {
        let value = value.to_string();
        self.write(value.as_bytes())
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
                _ => self.write(&[byte])?,
            }
        }
        self.write(b"\"")
    }
}

#[cfg(test)]
mod tests {
    use super::{Writer, write_entities, write_inline_markup, write_input_media};
    use trlib_core::generated::{
        INPUT_MEDIA_PHOTO_EXTERNAL, KEYBOARD_BUTTON_CALLBACK, KEYBOARD_BUTTON_ROW,
        MESSAGE_ENTITY_BOLD, REPLY_INLINE_MARKUP,
    };
    use trlib_core::tl::Cursor;

    #[test]
    fn serializes_message_entity_without_an_ast() {
        let mut output = [0u8; 128];
        let mut writer = Writer::new(&mut output);
        let entities = br#"[{"type":"bold","offset":0,"length":5}]"#;
        write_entities(&mut writer, entities, 1).expect("entity");
        let mut cursor = Cursor::new(writer.written());
        assert_eq!(
            cursor.read_constructor().expect("constructor"),
            MESSAGE_ENTITY_BOLD
        );
        assert_eq!(cursor.read_i32().expect("offset"), 0);
        assert_eq!(cursor.read_i32().expect("length"), 5);
    }

    #[test]
    fn serializes_external_photo_media() {
        let mut output = [0u8; 128];
        let mut writer = Writer::new(&mut output);
        write_input_media(
            &mut writer,
            "sendPhoto",
            br#"{"photo":"https://example.test/p.jpg"}"#,
        )
        .expect("media");
        let mut cursor = Cursor::new(writer.written());
        assert_eq!(
            cursor.read_constructor().expect("constructor"),
            INPUT_MEDIA_PHOTO_EXTERNAL
        );
    }

    #[test]
    fn serializes_inline_keyboard_buttons() {
        let mut output = [0u8; 256];
        let mut writer = Writer::new(&mut output);
        write_inline_markup(&mut writer, br#"[[{"text":"ok","callback_data":"1"}]]"#)
            .expect("markup");
        let mut cursor = Cursor::new(writer.written());
        assert_eq!(
            cursor.read_constructor().expect("markup"),
            REPLY_INLINE_MARKUP
        );
        assert_eq!(cursor.read_constructor().expect("vector"), super::VECTOR);
        assert_eq!(cursor.read_i32().expect("rows"), 1);
        assert_eq!(cursor.read_constructor().expect("row"), KEYBOARD_BUTTON_ROW);
        assert_eq!(cursor.read_constructor().expect("buttons"), super::VECTOR);
        assert_eq!(cursor.read_i32().expect("button count"), 1);
        assert_eq!(
            cursor.read_constructor().expect("button"),
            KEYBOARD_BUTTON_CALLBACK
        );
    }
}
