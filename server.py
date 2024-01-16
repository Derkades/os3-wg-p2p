import json
import socket
from dataclasses import dataclass

from connection import MAGIC_HEADER, ConnectionRequest, ConnectionResponse


def read_config():
    with open('server_config.json') as config_file:
        return json.load(config_file)


@dataclass
class ConnectionPeer:
    addr: tuple[str, int]
    req: ConnectionRequest


@dataclass
class Connection:
    a: ConnectionPeer
    b: ConnectionPeer


# Pending connections by UUID
PENDING_CONNECTIONS: dict[str, ConnectionPeer] = {}
# Connections by address
CONNECTIONS: dict[tuple[str, int], Connection] = {}


def handle_connection_request(data, addr, sock: socket.socket):
    if addr in CONNECTIONS:
        print('Already has connection, destroying previous connection')
        conn = CONNECTIONS[addr]
        del CONNECTIONS[conn.a.addr]
        del CONNECTIONS[conn.b.addr]

    req = ConnectionRequest.unpack(data)

    if req.uuid in PENDING_CONNECTIONS:
        conn = Connection(PENDING_CONNECTIONS[req.uuid], ConnectionPeer(addr, req))
        print('Second request, register connection:', conn)

        del PENDING_CONNECTIONS[req.uuid]
        if req.relay:
            CONNECTIONS[conn.a.addr] = conn
            CONNECTIONS[conn.b.addr] = conn

        # send A info to B
        resp = ConnectionResponse(conn.a.req.pubkey, conn.a.addr[0], conn.a.addr[1], conn.a.req.vpn_addr4, conn.a.req.vpn_addr6)
        sock.sendto(resp.pack(), conn.b.addr)

        # send B info to A
        resp = ConnectionResponse(conn.b.req.pubkey, conn.b.addr[0], conn.b.addr[1], conn.b.req.vpn_addr4, conn.b.req.vpn_addr6)
        sock.sendto(resp.pack(), conn.a.addr)
    else:
        pending = ConnectionPeer(addr, req)
        print('First request, register pending:', pending)
        PENDING_CONNECTIONS[req.uuid] = pending


def handle_other(data, addr, sock: socket.socket, verbose: bool):
    if addr not in CONNECTIONS:
        print('Ignoring message from unknown address:', addr)
        return

    conn = CONNECTIONS[addr]

    dest_addr = conn.b.addr if addr == conn.a.addr else conn.a.addr
    if verbose:
        print(f'Relaying message: {len(data)} bytes {addr} -> {dest_addr}')
    sock.sendto(data, dest_addr)


def main():
    config = read_config()
    verbose = config['verbose']

    bind_addr = ('0.0.0.0', config['server_port'])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind_addr)

    print('Listening on:', bind_addr)

    while True:
        data, addr = sock.recvfrom(2048)

        if data.startswith(MAGIC_HEADER):
            handle_connection_request(data[len(MAGIC_HEADER):], addr, sock)
            continue

        handle_other(data, addr, sock, verbose)


if __name__ == '__main__':
    main()
