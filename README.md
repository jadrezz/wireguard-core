# WireGuard Core

**REST API for WireGuard management.** A stateless HTTP API written in Go for managing a WireGuard VPN server: peer management (add, remove, disable, enable), configuration persistence, and server lifecycle (init, reset). Uses wgctrl, wg-quick, and iptables on Linux.

## Features

- **Devices** — List WireGuard interfaces (e.g. wg0).
- **Peers** — List peers with traffic stats and last handshake; create a peer (key generation, IP allocation, client config); remove peer; disable/enable peer via iptables DROP.
- **Address pool** — Count free tunnel addresses.
- **Server** — Initialize a new WireGuard server (config file, PostUp/PostDown, wg-quick up); reset server (wg-quick down, remove config and disabled-peers state).
- **API** — Health check, Swagger UI, OpenAPI 3.0 spec, request correlation with X-Request-ID.

## Requirements

- **Runtime:** Linux and root user.
- **Installed Wireguard and next binaries in PATH**: `wg`, `wg-quick`, `iptables`, `ip`. Config directory (e.g. `/etc/wireguard`) must be writable.
- **For manual build:** Go 1.25+.

## Configuration

Environment variables (see [config/config.go](config/config.go)):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WG_ENDPOINT` | yes | — | Server public IP (e.g. for client config) |
| `WG_PORT` | yes | — | UDP listen port |
| `WG_KEEP_ALIVE` | yes | — | Persistent keepalive (e.g. `25s`, `1m`) |
| `WG_DEFAULT_DNS` | no | `8.8.8.8` | Default DNS for new peer configs |
| `WG_CONFIG_DIR` | no | `/etc/wireguard` | Directory for config files |
| `WG_EXTERNAL_IFACE` | no | `eth0` | External interface for NAT/masquerade |

## Quick start

```bash
export WG_ENDPOINT=203.0.113.1
export WG_PORT=51820
export WG_KEEP_ALIVE=25s
go run ./cmd
```

Server listens on `:7777`. Open [http://localhost:7777/swagger/](http://localhost:7777/swagger/) for interactive API docs; spec at [http://localhost:7777/openapi.yaml](http://localhost:7777/openapi.yaml).

## API overview

Full documentation is available in Swagger UI and as OpenAPI 3.0 YAML. Endpoint groups: **Health** (liveness), **Devices** (list interfaces), **Peers** (CRUD, disable/enable, available addresses, peer info), **Server** (init, reset).
