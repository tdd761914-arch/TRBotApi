# TRBotApi

TRBotApi is a small Telegram Bot API edge built on the zero-copy MTProto
primitives from [TRLib](https://github.com/tdd761914-arch/TRLib).  It keeps the
HTTP/JSON contract at the edge and leaves authorization-key storage, sockets,
DC routing and update scheduling behind a transport trait.  The core has no
`serde`, Tokio, SQLite or allocator requirement.

This repository is an early high-throughput foundation, not a claim that one
blocking process already replaces Telegram's complete hosted Bot API.  The
reference edge is intentionally simple; a production deployment should use an
evented acceptor, sharded bot registry and a persistent MTProto reactor.

## Layout

- `trbotapi-core` — `no_std` bounded Bot API request parsing, JSON responses,
  the current 185-method [Bot API catalogue](https://core.telegram.org/bots/api#available-methods),
  `auth.importBotAuthorization`, `users.getFullUser`, text/rich `sendMessage`,
  URL media, media groups, and `rpc_result` extraction. All buffers are supplied
  by the caller.
- `trbotapi-server` — a small `std` HTTP/1.1 reference edge, per-bot locking,
  bounded update queues and a `BotTransport` hook for an epoll/io_uring
  MTProto implementation.
- `trbotapi.conf` — deployment profile without secrets.

## Run the reference edge

The smoke profile answers `getMe` for one configured bot.  It does not print
the token and it refuses to invent a Telegram network session:

```bash
export TRBOTAPI_BOT_TOKEN='123456:replace-me'
export TRBOTAPI_BOT_ID=123456
export TRBOTAPI_BOT_USERNAME=example_bot
export TRBOTAPI_BOT_FIRST_NAME='Example Bot'
cargo run --release -p trbotapi-server
```

Then:

```bash
curl -sS -X POST \
  'http://127.0.0.1:8080/bot123456:replace-me/getMe' \
  -H 'content-type: application/json' -d '{}'
```

The route shape and response envelope follow the Bot API.  All 185 current
method names are recognized case-insensitively.  The eight hot-path methods
(`getMe`, text `sendMessage`, `getUpdates`, `setWebhook`, `deleteWebhook`,
`getWebhookInfo`, `answerCallbackQuery`, and integer-id `getChat`) have bounded
typed parsing in the core. Rich `sendMessage` requests with `entities` and
basic inline keyboards stay borrowed and are converted to MTProto objects. The remaining methods are passed as borrowed JSON
to `BotTransport::call_bot_api`, so an embedding MTProto reactor can add a
mapping without changing the HTTP edge. `getUpdates` is currently a local
queue hook; a transport reactor must feed it from MTProto updates.

For a Test-DC smoke connection, provide API credentials and opt in explicitly:

```bash
export TRBOTAPI_API_ID=29806415
export TRBOTAPI_API_HASH='your-api-hash'
export TRBOTAPI_CONNECT_TEST_DC=1
cargo run --release -p trbotapi-server
```

The bundled transport uses TRLib's fixed Test-DC auth-key path. Production DC
key provisioning and a shared evented reactor remain deployment work.

## Connecting MTProto

The core serializes the MTProto methods directly through TRLib:

```rust
use trbotapi_core::{write_import_bot_authorization, write_get_me};

let mut body = [0u8; 512];
let import_len = write_import_bot_authorization(
    &mut body,
    api_id,
    api_hash,
    bot_token,
)?;
// Send `body[..import_len]` through a TRLib auth-key session.
let get_me_len = write_get_me(&mut body)?;
```

`auth.importBotAuthorization` is the MTProto bot-login method.  The server
application supplies the API credentials and the bot token; store the resulting
auth key in TRLib's encrypted session document rather than in this repository.

Implement `BotTransport` for the actual runtime:

```rust
impl BotTransport for MyMtprotoReactor {
    fn call(&mut self, method: &[u8], output: &mut [u8])
        -> trbotapi_core::Result<usize> {
        // Queue `method` in a TRLib encrypted session and render a Bot API
        // result object into `output` after rpc_result/update decoding.
        # todo!()
    }

    fn call_bot_api(&mut self, method: &str, body: &[u8], output: &mut [u8])
        -> trbotapi_core::Result<usize> {
        // Map any of the 185 catalogued Bot API methods to TL and render the
        // result object directly into `output`.
        # todo!()
    }
}
```

The reference edge deliberately does not hide a blocking socket or one OS
thread per bot.  For hundreds of thousands of mostly idle bots, keep only the
encrypted session metadata in the registry and activate a connection on demand;
for active bots, shard reactors by bot/session hash.

### RAM estimate per bot

As a planning estimate, one idle registry entry is roughly **0.5–2 KiB** plus
the token/name strings and the shared `HashMap` bucket overhead. An entry with
the bundled `TestDcTransport` adds about **0.3 KiB** for the 256-byte auth key
material; the operating-system TCP socket buffers are separate. A request can
temporarily use up to `MAX_FRAME` (1 MiB) while decoding a large MTProto frame,
but that buffer is not retained per idle bot. These are allocator/OS-dependent
estimates, not a capacity guarantee; a production reactor should pool frame
buffers and keep sessions event-driven.

## Compatibility boundary

This is not the TDLib compatibility branch.  TRLib's TDLib adapter now lives on
the separate [`tdlib-compat` branch](https://github.com/tdd761914-arch/TRLib/tree/tdlib-compat),
while the TRLib `main` branch used here stays free of that code.

The request layer recognizes the complete current method catalogue. The bundled
Test-DC transport has direct mappings for login, `getMe`/text and rich
`sendMessage`, URL-based `sendPhoto`/document-family methods, `sendMediaGroup`,
location/venue/contact/dice/poll, message delete/forward/copy/edit/reaction,
chat actions, `answerInlineQuery` for article results, and
`getStickerSet`/`getCustomEmojiStickers` requests. Multipart upload, Telegram
`file_id` decoding, full sticker-document/file-id conversion, and non-article
inline result types require the embedding media cache. The remaining payment,
business, passport and story methods are forwarded to the transport hook.
Before calling it a production-compatible Bot API server, add:

1. a production MTProto transport with DC migration, reconnect, server-salt
   repair and auth-key/session loading;
2. Bot API `Update` conversion and durable offset queues for long polling and
   webhook exclusivity;
3. media upload/download and file-id storage;
4. rate-limit/error mapping (`FLOOD_WAIT`, `SLOWMODE_WAIT`, retry-after);
5. result differential tests against the current official Bot API;
6. TLS termination, token hashing/rotation, metrics and an independent audit.

## Size and verification

The release profile uses `opt-level = "z"`, LTO, one codegen unit and aborting
panics.  The no-std core is checked separately from the std server:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo check -p trbotapi-core --no-default-features --locked
cargo build --release --locked -p trbotapi-server
```

### Recorded smoke benchmark

The following numbers were recorded on the development container on 2026-08-07
with the release profile above. They are a reference-edge measurement, not a
capacity promise for a production Bot API deployment:

| Check | Result |
| --- | ---: |
| `target/release/trbotapi-server` file size | 463,696 bytes |
| ELF `text + data + bss` (`size`) | 449,102 bytes |
| 20 sequential `getMe` POSTs, 2 workers, local loopback | 1.149 s |
| Same run, mean/request | 57.46 ms |
| Same run, requests/second | 17.40 |

The HTTP run used one fresh `curl` connection per request and the static
`getMe` profile, so it measures parsing, routing and response writing only; it
does not include Telegram network latency or MTProto encryption. Reproduce it
with the following command after starting the server on port `18080`:

```bash
start=$(date +%s%N); i=0
while [ "$i" -lt 20 ]; do
  curl --max-time 2 --no-keepalive -fsS -o /dev/null \
    -X POST 'http://127.0.0.1:18080/bot123456:replace-me/getMe' \
    -H 'content-type: application/json' -d '{}'
  i=$((i + 1))
done
end=$(date +%s%N)
awk -v n=20 -v ns="$((end - start))" \
  'BEGIN { printf "%.2f req/s, %.2f ms/request\n", n/(ns/1e9), ns/n/1e6 }'
```

For a live Telegram Test-DC run, supply a disposable test bot token and opt in
to the bundled transport. This benchmark is intentionally not run with a
credential stored in the repository:

```bash
export TRBOTAPI_API_ID=29806415
export TRBOTAPI_API_HASH='your-api-hash'
export TRBOTAPI_BOT_TOKEN='test-bot-token'
export TRBOTAPI_CONNECT_TEST_DC=1
time cargo run --release -p trbotapi-server
```

The command must complete `auth.importBotAuthorization` before serving HTTP;
record its wall time and then benchmark `getMe`/`sendMessage` against the
running edge. Production DC routing and a long-lived MTProto reactor are not
included in this Test-DC smoke path.

### Two-bot Test-DC measurement (2026-08-08)

Two disposable Test Bot API tokens were authenticated against Test DC 2 with
`auth.importBotAuthorization` (wrapped in `initConnection`). Each token ran in
its own release process on loopback with one HTTP worker. Credentials were
passed through the environment and were not written to the repository.

| Metric | Bot A | Bot B |
| --- | ---: | ---: |
| Test-DC authorization | pass | pass |
| HTTP worker / process threads | 1 / 2 | 1 / 2 |
| RSS immediately after startup | 2,992 KiB | 2,992 KiB |
| RSS after 100 requests | 4,160 KiB | 4,192 KiB |
| peak `VmHWM` during run | 5,432 KiB | 5,360 KiB |
| `smaps_rollup` PSS after run | 2,719 KiB | 2,823 KiB |
| virtual address space (`VmSize`) | 72,052 KiB | 72,052 KiB |
| 100 local `getMe` requests | 4.353 s | 4.258 s |
| loopback rate (fresh `curl` per request) | 22.97 req/s | 23.49 req/s |
| mean / p50 / p95 latency | 2.545 / 2.125 / 5.498 ms | 2.853 / 2.284 / 5.782 ms |

The release executable used for this run was 1,381,200 bytes (`size`:
`text+data+bss = 1,356,106` bytes). `getMe` is the allocation-light local
fast path, so these request numbers measure the HTTP parser, routing and JSON
writer; they do **not** measure a Telegram RPC round trip. The Test-DC auth
handshake is live, but the current reference transport needs an entity cache
with an `access_hash` before it can address an arbitrary user chat. RSS includes
the process/runtime and allocator state; PSS is the better estimate of private
RAM. Do not multiply the two process RSS values to predict a sharded process:
code pages and other read-only mappings can be shared, while active MTProto
frame buffers are workload-dependent.

TRBotApi is MIT licensed.
