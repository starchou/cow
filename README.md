# Proxy

Fork from: <https://github.com/cyfdecyf/cow>

## New Features

* default allow all ports
* `tunnelAllowedPort` support `*` to allow all ports.
* optional HTTP(S) and WebSocket traffic capture with an automatically generated CA.

## Traffic capture

Traffic capture is disabled by default. Add these options to the rc file:

```ini
capture = true
captureDir = ~/.cow/capture
captureDomainFile = ~/.cow/domain.list
```

The domain file contains one domain per line. Blank lines and lines beginning
with `#` are ignored; an entry also matches its subdomains. An empty file
captures nothing. Use a line containing only `*` when every domain should be
captured:

```text
# capture targets
example.com
api.service.local
```

Each request is saved under `captureDir/logs` as
`host_target-filename_YYYYMMDD_HHMMSS.nanoseconds.log`. The `logs` directory is
created automatically.
WebSocket data is appended to its handshake log in both directions. HTTPS and
WSS are decrypted locally with a generated CA. On first start, COW creates
`cow-ca.crt` and `cow-ca.key` in `captureDir`; keep the private key secret.

SOCKS5 connections are captured when they contain a recognized HTTP method or
a TLS ClientHello advertising HTTP. TLS without ALPN is captured on ports 443
and 8443. Other SOCKS5 protocols remain byte-for-byte transparent. With a
SOCKS5-only listener, copy `cow-ca.crt` from `captureDir`; add an HTTP listener
if the certificate also needs to be downloadable over `/cow-ca.crt`.

Download the public CA from `http://<proxy-address>/cow-ca.crt`, then install
it as a trusted root on the client. For example on macOS:

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.cow/capture/cow-ca.crt
```

Certificate pinning is intentionally not bypassed. Capture logs contain full
request and response data, including credentials and cookies; use this only on
systems and traffic you are authorized to inspect.

## Install

### Docker

```sh
docker run -p 7777:7777 ppcelery/cow:latest
```

you can mount your own config rc to `/etc/cow/rc`

### Manual

```sh
go install github.com/Laisky/cow@latest
```

Show Sample config:

(save your config file at `$HOME/.cow/rc`)

```sh
# write default config
cow -sample > $HOME/.cow/rc
```

Add systemd service:

```sh
# check
cow -systemd

# install systemd service
cow -systemd > /etc/systemd/system/cow.service

sudo systemctl enable --now cow
```
