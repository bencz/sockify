# sockify

A small proxy that accepts WebSocket connections and forwards the bytes to a plain TCP server.

Same idea as `websockify` from the noVNC project: you have a TCP service that does not speak WebSocket (VNC, SSH, a database, anything) and you want to expose it to a client that only speaks WebSocket, usually a browser. sockify sits in the middle, does the WebSocket handshake with the client, opens a regular TCP connection to the target, and from there it just shuttles payload bytes back and forth.

Written in plain C89. No CMake, no required dependencies beyond libc. OpenSSL is optional and only pulled in when you actually turn TLS on.

## Build

```sh
make
make test
```

Works on Linux, macOS, BSDs and Windows. Linux uses epoll, macOS and BSDs use kqueue, Windows uses Winsock2 with a skeleton IOCP backend. If `pkg-config` finds OpenSSL, TLS support is enabled automatically.

## Use

```sh
./build/sockify 127.0.0.1:6080 127.0.0.1:5900
```

First argument is where sockify listens, second is the TCP target. There is no default listen host, so be explicit: use `127.0.0.1:PORT` for local only, or `0.0.0.0:PORT` if you want it reachable from anywhere.

The classic case is putting a VNC server behind a noVNC browser client, but it works for any TCP service.

## Options

```
--help
--version
--max-connections N
--buffer-size N
--handshake-timeout MS
--idle-timeout MS
--connect-timeout MS
--log-level error|warn|info|debug
--client-tls
--client-tls-cert FILE
--client-tls-key FILE
--client-tls-pfx FILE
--client-tls-pfx-password PASS
--client-tls-cert-store STORE
--client-tls-cert-thumbprint HEX
--target-tls
--target-tls-server-name NAME
--target-tls-ca-file FILE
--target-tls-insecure
```

Timeouts are in milliseconds. Defaults are 10s for the WebSocket handshake, 10s for the target connect, and 5min of idle on an established session. Pass `0` to any of them to disable.

## TLS

There are two independent TLS legs. The ingress leg is the WebSocket side (`--client-tls`), and the egress leg is the connection to the target (`--target-tls`). You can turn either of them on, both, or neither, and they do not need to match.

### Plain on both sides

Default. No flags. The client speaks `ws://` and the target is plain TCP.

### TLS only on the WebSocket side

The most common case. The browser speaks `wss://`, but the backend you are forwarding to is plain TCP (a VNC server on localhost, for instance).

```sh
./build/sockify --client-tls \
                --client-tls-cert server.pem \
                --client-tls-key server.key \
                0.0.0.0:6080 127.0.0.1:5900
```

### TLS only to the target

The client speaks `ws://` but the target requires TLS. Useful when sockify and the client live on a trusted network, but the target is a remote TLS service.

```sh
./build/sockify --target-tls \
                --target-tls-server-name target.example.com \
                127.0.0.1:6080 target.example.com:443
```

### TLS on both sides

Independent contexts, independent certs. The ingress cert is the one your client sees, the egress side is just a TLS client verifying the target.

```sh
./build/sockify --client-tls \
                --client-tls-cert server.pem \
                --client-tls-key server.key \
                --target-tls \
                --target-tls-server-name target.example.com \
                0.0.0.0:6080 target.example.com:443
```

### Loading the ingress certificate

You only need one of these three sources for `--client-tls`:

- PEM files, with `--client-tls-cert FILE` and `--client-tls-key FILE`. This is the only form the OpenSSL backend (Linux and macOS) supports today.
- PFX/PKCS12 file, with `--client-tls-pfx FILE` and optionally `--client-tls-pfx-password PASS`. Only the Windows Schannel backend will consume this, and that backend is not production ready yet.
- Windows Certificate Store, with `--client-tls-cert-store STORE` and `--client-tls-cert-thumbprint HEX`. Same as above, Windows only and not finished.

If `--client-tls` is on, exactly one of those sources must be provided, and `--client-tls-cert` always goes paired with `--client-tls-key`.

### Verifying the target

When `--target-tls` is on, the target certificate is verified against the system trust store by default. The relevant flags:

- `--target-tls-server-name NAME` sets the SNI and the hostname checked against the certificate. If you leave it out, the target host you passed on the command line is used.
- `--target-tls-ca-file FILE` adds a custom CA bundle, useful for private CAs or self signed setups. System CAs are still consulted.
- `--target-tls-insecure` turns verification off entirely. Only use this in controlled test setups.

## Notes

WebSocket frames are parsed in streaming mode, so each session does not reserve a huge payload buffer up front. Per direction buffers are bounded and use high and low water marks to keep memory under control. Accept, read and write loops have a per call budget, so one noisy client cannot starve the rest of the event loop.

Sessions that never complete the handshake, never connect to the target, or sit idle for too long are dropped automatically based on the timeout flags above. Sockets are configured with `TCP_NODELAY` to keep latency low on interactive payloads. On the TLS side, renegotiation is disabled and a server side session cache is enabled so reconnecting clients pay less.

On Windows the IOCP backend is sketched out but not production ready yet: Schannel, PFX and Certificate Store loading, and full IOCP completion dispatch are still on the list.
