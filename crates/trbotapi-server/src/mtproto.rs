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

use trbotapi_core::{Error, ErrorKind, Result, rpc_result_body, write_import_bot_authorization};
use trlib_core::api::parse_auth_response;
use trlib_core::auth_key::{AuthKeyHandshake, AuthKeyMaterial, RandomSource};
use trlib_core::crypto::{AuthKeyRef, CryptoDirection, RustCrypto, SessionCrypto};
use trlib_core::generated::messages::MESSAGES_SEND_MESSAGE;
use trlib_core::mtproto::{
    ExternalEnvelope, OutboundMessage, encode_encrypted, parse_decrypted, parse_external,
};
use trlib_core::tl::{ConstructorId, Cursor, Writer};
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
        let mut import = [0u8; 1024];
        let import_len = write_import_bot_authorization(&mut import, api_id, api_hash, bot_token)?;
        let mut result = vec![0u8; MAX_FRAME];
        let result_len = value.call_raw(&import[..import_len], &mut result)?;
        match parse_auth_response(&result[..result_len]).map_err(Error::from)? {
            trlib_core::api::AuthResponse::Authorized(_) => Ok(value),
            trlib_core::api::AuthResponse::RpcError(error) => {
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
}
