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
```

Each request is saved as `host_target-filename_YYYYMMDD_HHMMSS.nanoseconds.log`.
WebSocket data is appended to its handshake log in both directions. HTTPS and
WSS are decrypted locally with a generated CA. On first start, COW creates
`cow-ca.crt` and `cow-ca.key` in `captureDir`; keep the private key secret.

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
