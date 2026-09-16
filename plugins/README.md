# HTTP plugins

`masterrummy` is a built-in COW module for `com.x69l.r916z.a572` (`channel_id=2000572`).
Enable it in the rc file:

```ini
plugin = masterrummy
pluginDBFile = ~/.cow/plugins.sqlite3
```

Comment out `plugin` to disable it. The default DB location is `plugins.sqlite3`
beside the rc file; its parent directory, table and indexes are created on startup.
An unknown plugin name or an unusable database path produces a startup error.

Plain HTTP is observed independently of file capture. For HTTPS and HTTP(S) over
SOCKS5, also enable the existing capture path, trust its CA and add the target
domains to `captureDomainFile`. Unlisted TLS traffic stays transparent:

```ini
capture = true
captureDir = ~/.cow/capture
captureDomainFile = ~/.cow/domain.list
```

Example `domain.list` (use the domains actually contacted by the app):

```text
api.masterummy.com
api.masterummy.xyz
```

## Protocol and insertion rule

The verified a572 protocol is `/i.php?<percent-encoded Base64 AES ciphertext>`.
POST bodies carrying the same encrypted query are also supported. The module uses
the APK's ASCII AES-256-CBC key/IV and strictly validates PKCS7 padding and UTF-8.
The plaintext request is a query string whose `param` value is JSON. Requests must
contain an action and `param.channel_id=2000572` to be attributed to this package.

The response must be `aes#<Base64 AES ciphertext>` and decrypt to a JSON object.
If it includes an action, that action must agree with the request. Both sides
must pass these checks before insertion; a valid encrypted application error
(for example `ret != 0`) is still recorded. Plaintext, invalid, incomplete and
other-package exchanges are skipped. MD5 business-signature verification is not
part of the insertion rule. `/api.php` ShareClient and WS frames are not handled
by this decoder.

Transport decoding removes chunking, then gzip or deflate (zlib/raw), before AES.
It receives bytes from the proxy directly; the Base64 formatting in capture log
files is not applied to the live stream. Unrecognized content encodings are skipped.
The AES configuration is recorded in `masterrummy/masterrummy.go`; it was checked
against the existing a572 analyzer and 36 locally available capture pairs.

## SQLite schema

Table: `plugin_http_records` (one complete request/response transaction per row).

| Columns | Contents |
| --- | --- |
| `id`, `plugin`, `package_name` | Row identity, module, verified package attribution |
| `domain`, `method`, `url`, `status_code` | Host, method, original request target (including encrypted query), HTTP status |
| `request_time_ns`, `request_time` | Request-line capture time: Unix nanoseconds and RFC3339Nano with timezone |
| `request_headers`, `response_headers` | BLOBs of the proxy's normalized HTTP headers, including start lines |
| `request_body`, `response_body` | BLOBs of forwarded bytes, including HTTP chunk framing/content encoding where present |
| `request_plaintext`, `response_plaintext` | Exact AES plaintext before structured parsing |
| `parsed_request`, `parsed_response` | JSON text; request `param` is parsed as an object |
| `action`, `uid` | Request action; response `uid`, falling back to `data.uid` |

`uid` is TEXT to preserve large numeric IDs exactly, and NULL when absent. It is
never inferred from the request's `sid`. Embedded JSON strings in responses, such
as `data.ext_info`, remain strings in the stored JSON to preserve their values.

Indexes: `(action, request_time_ns DESC)`, `(uid, request_time_ns DESC)`,
`(domain, request_time_ns DESC)` and `(request_time_ns DESC)`.

```sql
SELECT request_time, domain, action, uid, parsed_response
FROM plugin_http_records
WHERE action = 'NPayProxy'
ORDER BY request_time_ns DESC LIMIT 20;

SELECT request_time, action, parsed_request, parsed_response
FROM plugin_http_records
WHERE uid = '12345'
ORDER BY request_time_ns DESC LIMIT 100;
```

## Asynchronous behavior

The proxy copies at most 1 MiB of each header/body and makes a nonblocking queue
submission. A single background worker handles transport decoding, AES and SQL;
SQLite uses WAL, one writer connection, and a three-second busy timeout. No
database operations run in the request forwarding path.

There are at most 64 admitted transactions in total, including requests currently
being forwarded, queued records and the active DB write. Full capacity, oversized
bodies/headers, and shutdown drop records; the proxy continues serving traffic.
Decompressed bodies also have a 1 MiB limit. Drop counts are reported from the
worker every 30 seconds when changed. DB write errors are logged and counted.
This is a best-effort capture queue, not a lossless audit log.

On normal exit or relaunch, new admission stops and already queued records drain.
Requests still in progress at shutdown and forced process kills are not guaranteed
to be recorded. Summary counters report stored, skipped, dropped and DB errors.

## Checks

```sh
go test -run 'TestMasterrummy|TestPlugin' .
go test -race -run 'TestMasterrummy|TestPlugin' .
```

These cover HTTP and HTTPS through both HTTP and SOCKS5 listeners, a locked DB,
gzip/chunked decoding, invalid ciphertext, large UIDs, bounded admission and indexes.
Optional offline validation of existing COW logs (only aggregate counts printed):

```sh
COW_A572_LOG_DIR=/path/to/domain-log-folder go test -run TestPluginLocalA572Logs -v .
```
