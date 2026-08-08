# TRBotApi

TRBotApi — лёгкий HTTP-шлюз Telegram Bot API поверх zero-copy MTProto-ядра
[TRLib](https://github.com/tdd761914-arch/TRLib). HTTP/JSON остаётся на edge,
а хранение auth key, сокеты, DC routing и очередь updates передаются runtime.
В core нет `serde`, Tokio, SQLite и обязательного allocator.

Это ранний фундамент high-throughput сервера, а не утверждение, что один
блокирующий процесс уже заменяет полный hosted Bot API Telegram. Reference edge
намеренно небольшой; для production нужны evented acceptor, sharded registry и
реактор MTProto.

## Структура

- `trbotapi-core` — `no_std` bounded JSON parser, полный текущий каталог из
  185 имён [Bot API](https://core.telegram.org/bots/api#available-methods),
  `auth.importBotAuthorization`, `users.getFullUser`, text/rich `sendMessage`,
  URL media, media groups и извлечение `rpc_result`.
- `trbotapi-server` — небольшой HTTP/1.1 edge на `std`, per-bot locks,
  bounded update queue и trait `BotTransport` для epoll/io_uring runtime.
- `trbotapi.conf` — профиль без секретов.

## Запуск reference edge

Smoke-профиль отвечает на `getMe` для одного настроенного бота. Токен не
печатается и сервер не притворяется подключённым к Telegram без transport:

```bash
export TRBOTAPI_BOT_TOKEN='123456:replace-me'
export TRBOTAPI_BOT_ID=123456
export TRBOTAPI_BOT_USERNAME=example_bot
export TRBOTAPI_BOT_FIRST_NAME='Example Bot'
cargo run --release -p trbotapi-server
```

Проверка:

```bash
curl -sS -X POST \
  'http://127.0.0.1:8080/bot123456:replace-me/getMe' \
  -H 'content-type: application/json' -d '{}'
```

Все 185 текущих имён методов распознаются без учёта регистра. Для hot path
(`getMe`, текстовый `sendMessage`, `getUpdates`, `setWebhook`,
`deleteWebhook`, `getWebhookInfo`, `answerCallbackQuery` и integer-id `getChat`)
есть bounded typed parser. Rich `sendMessage` с `entities` остаётся заимствованным
и конвертируется в MTProto `MessageEntity`. Остальные методы передаются как заимствованный
JSON в `BotTransport::call_bot_api`, поэтому MTProto reactor может добавлять
mapping без изменения HTTP edge. `getUpdates` пока является локальным queue
hook: transport reactor должен заполнять его из MTProto updates.

Для smoke-подключения к Test DC нужно явно передать API credentials:

```bash
export TRBOTAPI_API_ID=29806415
export TRBOTAPI_API_HASH='your-api-hash'
export TRBOTAPI_CONNECT_TEST_DC=1
cargo run --release -p trbotapi-server
```

Встроенный transport использует fixed Test-DC auth-key path TRLib. Production
DC keys и общий evented reactor пока остаются задачей deployment.

## Подключение MTProto

Core пишет методы через TRLib напрямую:

```rust
use trbotapi_core::{write_import_bot_authorization, write_get_me};

let mut body = [0u8; 512];
let import_len = write_import_bot_authorization(
    &mut body, api_id, api_hash, bot_token,
)?;
// Отправить body[..import_len] через TRLib auth-key session.
let get_me_len = write_get_me(&mut body)?;
```

`auth.importBotAuthorization` — MTProto-метод входа бота. API credentials и
bot token передаёт приложение; полученный auth key следует хранить через
зашифрованный session document TRLib, а не в репозитории.

Reference edge не создаёт поток или blocking socket на каждого бота. Для сотен
тысяч в основном idle-ботов храните только зашифрованные session metadata и
поднимайте соединение по требованию; активные сессии распределяйте по shard
reactors.

Для собственного transport реализуйте оба метода trait: `call` для уже
сериализованных TL-вызовов и `call_bot_api(method, body, output)` для полного
каталога Bot API. `body` заимствуется из HTTP buffer и не превращается в JSON
AST.

## Граница совместимости

Это не TDLib-ветка. TDLib adapter TRLib вынесен в отдельную ветку
[`tdlib-compat`](https://github.com/tdd761914-arch/TRLib/tree/tdlib-compat), а
ветка `main`, используемая здесь, остаётся лёгкой.

HTTP-слой принимает полный каталог методов. Bundled Test-DC transport уже
имеет mapping для login, `getMe`/текстового и rich `sendMessage`, URL-based
`sendPhoto`/document-family, `sendMediaGroup`, location/venue/contact/dice/poll,
delete/forward/copy/edit/reaction сообщений, chat actions, `answerInlineQuery`
для article results и запросов `getStickerSet`/`getCustomEmojiStickers`.
Multipart upload, Telegram `file_id` decoding, полноценная конвертация sticker
documents/file_id и inline result types кроме article требуют embedding media
cache. Остальные payment, business, passport и story методы проходят в
transport hook. До фактической production-совместимости с полным Bot API нужны:

1. production MTProto transport с DC migration, reconnect, server-salt repair
   и загрузкой auth key/session;
2. конвертация MTProto Update в Bot API Update и durable offset queue для
   long polling/webhook;
3. media upload/download и file-id storage;
4. mapping `FLOOD_WAIT`/`SLOWMODE_WAIT`/retry-after;
5. differential tests против текущего официального Bot API;
6. TLS, token hashing/rotation, metrics и независимый security audit.

## Проверка

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo check -p trbotapi-core --no-default-features --locked
cargo build --release --locked -p trbotapi-server
```

### Зафиксированный smoke-бенчмарк

Ниже — измерения в development-контейнере 2026-08-07 с release-профилем
проекта. Это benchmark reference edge, а не обещание production capacity:

| Проверка | Результат |
| --- | ---: |
| Размер `target/release/trbotapi-server` | 463 696 байт |
| ELF `text + data + bss` (`size`) | 449 102 байт |
| 20 последовательных `getMe` POST, 2 worker, loopback | 1,149 с |
| Среднее время запроса | 57,46 мс |
| Запросов в секунду | 17,40 |

HTTP-run использовал новое `curl`-соединение на каждый запрос и статический
профиль `getMe`, поэтому измеряет parser, routing и запись ответа без сетевой
задержки Telegram и MTProto-шифрования. Повторить его можно так (сервер уже
должен слушать порт `18080`):

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

Для живого запуска через Telegram Test DC передайте одноразовый test bot
token и явно включите встроенный transport. Этот benchmark намеренно не
запускается с credential, сохранённым в репозитории:

```bash
export TRBOTAPI_API_ID=29806415
export TRBOTAPI_API_HASH='your-api-hash'
export TRBOTAPI_BOT_TOKEN='test-bot-token'
export TRBOTAPI_CONNECT_TEST_DC=1
time cargo run --release -p trbotapi-server
```

Команда сначала должна завершить `auth.importBotAuthorization`, затем можно
замерить `getMe`/`sendMessage` через работающий edge. Production DC routing и
долгоживущий MTProto reactor в этот Test-DC smoke path не входят.

TRBotApi распространяется под MIT.
