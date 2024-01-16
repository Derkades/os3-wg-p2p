import json
import socket
from dataclasses import dataclass
import logging

from connection import MAGIC_HEADER, ConnectionRequest, ConnectionResponse


log = logging.getLogger('server')


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
        log.warning('already has connection, destroying previous connection')
        conn = CONNECTIONS[addr]
        del CONNECTIONS[conn.a.addr]
        del CONNECTIONS[conn.b.addr]

    req = ConnectionRequest.unpack(data)

    if req.uuid in PENDING_CONNECTIONS:
        conn = Connection(PENDING_CONNECTIONS[req.uuid], ConnectionPeer(addr, req))
        log.info('second request from %s, register connection', addr)
        log.debug('conn: %s', conn)

        del PENDING_CONNECTIONS[req.uuid]
        if req.relay:
            CONNECTIONS[conn.a.addr] = conn
            CONNECTIONS[conn.b.addr] = conn

        # send A info to B
        resp_a = ConnectionResponse(conn.a.req.pubkey, conn.a.addr[0], conn.a.addr[1], conn.a.req.vpn_addr4, conn.a.req.vpn_addr6)
        log.debug('send response to a: %s', resp_a)
        sock.sendto(resp_a.pack(), conn.b.addr)

        # send B info to A
        resp_b = ConnectionResponse(conn.b.req.pubkey, conn.b.addr[0], conn.b.addr[1], conn.b.req.vpn_addr4, conn.b.req.vpn_addr6)
        log.debug('send response to b: %s', resp_b)
        sock.sendto(resp_b.pack(), conn.a.addr)
    else:
        pending = ConnectionPeer(addr, req)
        log.info('first request from %s, register pending', addr)
        log.debug('peer: %s', pending)
        PENDING_CONNECTIONS[req.uuid] = pending


def handle_other(data, addr, sock: socket.socket):
    if addr not in CONNECTIONS:
        log.info('ignoring message from unknown address: %s', addr)
        return

    conn = CONNECTIONS[addr]

    dest_addr = conn.b.addr if addr == conn.a.addr else conn.a.addr
    log.debug('relaying message: %s bytes %s -> %s', len(data), addr, dest_addr)
    sock.sendto(data, dest_addr)


def main():
    config = read_config()
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_addr = ('0.0.0.0', config['server_port'])
    log.info('listening on %s', bind_addr)
    sock.bind(bind_addr)

    while True:
        data, addr = sock.recvfrom(2048)

        if data.startswith(MAGIC_HEADER):
            handle_connection_request(data[len(MAGIC_HEADER):], addr, sock)
            continue

        handle_other(data, addr, sock)


if __name__ == '__main__':
    main()
