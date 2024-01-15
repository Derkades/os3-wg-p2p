import json
import socket
from dataclasses import dataclass

from connection import MAGIC_HEADER, ConnectionRequest, ConnectionResponse


def read_config():
    with open('server_config.json') as config_file:
        return json.load(config_file)

@dataclass
class PendingConnection():
    req: ConnectionRequest
    addr: tuple[str, int]


class Connection:
    relay: bool
    peer1_pubkey: bytes
    peer1_addr: tuple[str, int]
    peer1_vpn_addr: bytes
    peer2_pubkey: bytes
    peer2_vpn_addr: bytes
    peer2_addr: tuple[str, int]

    def __init__(self, pending: PendingConnection, req: ConnectionRequest, addr: tuple[str, int]):
        assert req.relay == pending.req.relay
        self.relay = req.relay
        self.peer1_pubkey = pending.req.pubkey
        self.peer1_addr = pending.addr
        self.peer1_vpn_addr = pending.req.vpn_addr
        self.peer2_pubkey = req.pubkey
        self.peer2_vpn_addr = req.vpn_addr
        self.peer2_addr = addr


# Pending connections by UUID
PENDING_CONNECTIONS: dict[str, PendingConnection] = {}
# Connections by address
CONNECTIONS: dict[tuple[str, int], Connection] = {}

def destroy_connection(connection: Connection):
    del CONNECTIONS[connection.peer1_addr]
    del CONNECTIONS[connection.peer2_addr]


def handle_connection_request(data, addr, sock: socket.socket):
    if addr in CONNECTIONS:
        print('Already has connection, destroying previous connection')
        destroy_connection(CONNECTIONS[addr])

    req = ConnectionRequest.unpack(data)

    if req.uuid in PENDING_CONNECTIONS:
        pending = PENDING_CONNECTIONS[req.uuid]
        del PENDING_CONNECTIONS[req.uuid]
        print('Second request, register connection:', pending)

        conn = Connection(pending, req, addr)

        CONNECTIONS[conn.peer1_addr] = conn
        CONNECTIONS[conn.peer2_addr] = conn

        # send peer2 info to peer1
        resp = ConnectionResponse(conn.peer2_pubkey, conn.peer2_addr[0].encode(), conn.peer2_addr[1], conn.peer2_vpn_addr)
        sock.sendto(resp.pack(), conn.peer1_addr)

        # send peer1 info to peer2
        resp = ConnectionResponse(conn.peer1_pubkey, conn.peer1_addr[0].encode(), conn.peer1_addr[1], conn.peer1_vpn_addr)
        sock.sendto(resp.pack(), conn.peer2_addr)
    else:
        print('First request, register pending')
        PENDING_CONNECTIONS[req.uuid] = PendingConnection(req, addr)


def handle_other(data, addr, sock: socket.socket, verbose: bool):
    if addr not in CONNECTIONS:
        print('Ignoring message from unknown address:', addr)
        return

    conn = CONNECTIONS[addr]

    if not conn.relay:
        print('Received unknown message, but relaying is disabled')
        return

    dest_addr = conn.peer2_addr if addr == conn.peer1_addr else conn.peer1_addr
    if verbose:
        print(f'Relaying message: {len(data)} bytes {addr} -> {dest_addr}')
    sock.sendto(data, dest_addr)


def main():
    config = read_config()
    verbose = config['verbose']

    bind_addr = ('0.0.0.0', config['server_port'])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind_addr)

    print('listening on:', bind_addr)

    while True:
        data, addr = sock.recvfrom(1420)

        if data.startswith(MAGIC_HEADER):
            handle_connection_request(data[len(MAGIC_HEADER):], addr, sock)
            continue

        handle_other(data, addr, sock, verbose)


if __name__ == '__main__':
    main()
