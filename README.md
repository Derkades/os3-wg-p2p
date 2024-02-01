# Peer to peer WireGuard

Example of a VPN client and server that allows creating a peer to peer mesh network using WireGuard, without modifications to WireGuard itself. Uses UDP hole punching or a relay server. Fully supports IPv4 and IPv6 inside the tunnel, for peer to peer connections, for the relay server and the management server.

## Requirements

Install `wireguard-tools` and a recent version of Python 3. No Python dependencies are required.

Additional requirements to use NetworkManager `python3-gi` (Debian) or `python3-gobject` (Fedora)

## Server

Create the configuration file `server_config.json`:
```json
{
    "server_port": 3000,
    "log_level": "INFO"
}
```

`log_level` can be change to `DEBUG` for increased log output. The server runs a TCP and UDP server, ensure incoming traffic is allowed for both protocols.

Run: `python3 server.py`

## Client

Create the configuration file `client_config.json`:
```json
{
    "uuid": "b20b3973-6dcd-43be-a097-e80126ae6532",
    "address4": "10.200.0.1",
    "address6": "fdf0:a1e8:32b1:200::1",
    "server_host": "localhost",
    "server_port": 3000,
    "log_level": "INFO",
    "network_manager": false
}
```

- Every peer in a mesh network needs to be configured with the same UUID. A UUID can be generated using `uuidgen` or `python3 -m uuid`.
- Each peer should use a unique IPv4 and IPv6 address. The IPv4 address will be part of a /24 network, the IPv6 address part of a /64 network. The IPv4 address should usually be in `10.0.0.0/8` or `172.16.0.0/12`, `192.168.0.0/16`. The IPv6 address should usally be chosen from the `fd00::/8` range, in the `fdss:ssss:ssss:nnnn::/64` format `s` is a randomly chosen global ID and `n` the network ID.
- The client must be started with elevated privileges.
- `log_level` can be change to `DEBUG` for increased log output.
- `network_manager` can be set to `true` to use NetworkManager via DBus or `false` to run `ip` / `wg` commands. Warning: the NetworkManager implementation appears to have some race condition issues and cannot determine per-peer RX bytes.

Run `sudo python3 client.py`
