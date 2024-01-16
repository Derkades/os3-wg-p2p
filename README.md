# Peer to peer WireGuard

Simple wrapper script that allows creating peer to peer WireGuard tunnels with user defined networks. Uses UDP hole punching or a relay server. Supports IPv4 and IPv6.

`client_config.json`:
```json
{
    "uuid": "b20b3973-6dcd-43be-a097-e80126ae6532",
    "address4": "10.200.0.1",
    "address6": "fdf0:a1e8:32b1:200::1",
    "privkey": "ULDD6isz4gjfGcDhEjIchYzpDsGcvgLwix+OX9eKM3w=",
    "pubkey": "StCkEsOZoJnPbzYm7ydU54dqgPsBnyfyc/SvFE+gSXE=",
    "interface": "wg5",
    "server_host": "localhost",
    "server_port": 3000
}
```

UUID can be generated using `python3 -m uuid` and should be set to the same value on both ends of the tunnel. IPv4 uses /24 network, IPv6 uses /64 network. Generate privkey and pubkey using `wg genkey` and `wg pubkey`.

`server_config.json`:
```json
{
    "server_port": 3000,
    "verbose": true
}
```
