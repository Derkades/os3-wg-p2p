import json
import logging
import queue
import select
import time
from dataclasses import dataclass
from ipaddress import IPv6Address
from multiprocessing.pool import ThreadPool
from pathlib import Path
from socket import (AF_INET6, SHUT_RD, SO_REUSEADDR, SOCK_DGRAM, SOCK_STREAM,
                    SOL_SOCKET, socket)
from threading import Thread

import messages
from messages import MAGIC, AddressResponse, PeerHello, PeerInfo, PeerList

log = logging.getLogger('server')

@dataclass
class Peer:
    """Device (a WireGuard interface) in a network"""
    sock: socket
    addr4: tuple[str, int]
    addr6: tuple[str, int]
    pubkey: str
    vpn_addr4: str
    vpn_addr6: str


@dataclass
class Network:
    """Network of peers"""
    uuid: str
    peers: list[Peer]


NETWORK_BY_UUID: dict[str, Network] = {}
NETWORK_BY_ADDR: dict[tuple[str, int], Network] = {}  # for relay only
SOCKETS: set[socket] = set()
POOL = ThreadPool(32)


class Server:
    inputs: list[socket] = []
    outputs: list[socket] = []
    queues: dict[socket, queue.Queue] = {}
    sock_to_peer: dict[socket, tuple[Network, Peer]] = {}

    def send(self, sock: socket, data: bytes):
        self.queues[sock].put(data)
        self.outputs.append(sock)

    def close(self, sock: socket):
        log.debug('closing socket')
        self.inputs.remove(sock)
        if sock in self.outputs:
            self.outputs.remove(sock)
        sock.close()
        self.remove_peer(sock)

    def remove_peer(self, sock: socket):
        if sock in self.sock_to_peer:
            net, peer = self.sock_to_peer[sock]
            log.info('removing disconnected peer: %s', peer)
            net.peers.remove(peer)
            del self.sock_to_peer[sock]
            self.broadcast_peers(net.peers)
        else:
            log.debug('socket closed without disconnecting peer')

    def broadcast_peers(self, peers: list[Peer]):
        log.info('broadcast updated peer list to %s peers', len(peers))
        peer_list = PeerList([PeerInfo(peer.addr4, peer.addr6, peer.pubkey, peer.vpn_addr4, peer.vpn_addr6) for peer in peers])
        peer_list_bytes = messages.pack(peer_list)
        def send(peer: Peer):
            self.send(peer.sock, peer_list_bytes)
        POOL.map(send, peers)

    def handle_peer_hello(self, data, sock):
        hello: PeerHello = messages.unpack(data)
        if not hello:
            log.warning('ignoring invalid message from client')
            return

        log.debug('received hello: %s', hello)

        new_peer = Peer(sock, hello.addr4, hello.addr6, hello.pubkey, hello.vpn_addr4, hello.vpn_addr6)
        log.debug('new peer: %s', new_peer)

        if hello.uuid in NETWORK_BY_UUID:
            log.info('joining peer %s onto existing network %s', hello.pubkey, hello.uuid)
            net = NETWORK_BY_UUID[hello.uuid]
            net.peers.append(new_peer)
        else:
            log.info('registered new network %s for peer %s', hello.uuid, hello.pubkey)
            net = Network(hello.uuid, [new_peer])
            NETWORK_BY_UUID[hello.uuid] = net

        if hello.addr4:
            # IPv4 needs to be added as IPv4-mapped IPv6 address
            NETWORK_BY_ADDR[hello.addr4] = net
        if hello.addr6:
            NETWORK_BY_ADDR[hello.addr6] = net

        self.sock_to_peer[sock] = (net, new_peer)

        self.broadcast_peers(net.peers)

    def start(self, config):
        with socket(AF_INET6, SOCK_STREAM) as server:
            server.setblocking(0)
            server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            # Bind to IPv6 only
            # Dual stack mode accepts IPv4 connections using IPv4-mapped IPv6 address
            server.bind(('::', config['server_port']))
            server.listen()
            log.info('management server listening on [%s]:%s', server.getsockname()[0], server.getsockname()[1])
            SOCKETS.add(server)
            self.inputs.append(server)

            while self.inputs:
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)

                for sock in readable:
                    if sock is server:
                        client_sock, client_addr = sock.accept()
                        log.debug('new client connected from %s', client_addr)
                        self.inputs.append(client_sock)
                        self.queues[client_sock] = queue.Queue()
                        continue

                    data = sock.recv(16384)
                    if data:
                        self.handle_peer_hello(data, sock)
                    else:
                        self.close(sock)

                for sock in writable:
                    try:
                        next_msg = self.queues[sock].get_nowait()
                    except queue.Empty:
                        self.outputs.remove(sock)
                    else:
                        sock.send(next_msg)

                for sock in exceptional:
                    self.close(sock)

        log.debug('mgmt exit')


class Relay:
    def start(self, config):
        with socket(AF_INET6, SOCK_DGRAM) as sock:
            SOCKETS.add(sock)
            # Bind to IPv6 only
            # Dual stack mode accepts IPv4 connections using IPv4-mapped IPv6 address
            sock.bind(('::', config['server_port']))
            log.info('relay server listening on [%s]:%s', sock.getsockname()[0], sock.getsockname()[1])
            while True:
                data, s_addr = sock.recvfrom(1024)

                if data == b'':
                    log.debug('udp socket is dead')
                    break

                if data == MAGIC:
                    log.info('sending address response to %s', s_addr)
                    sock.sendto(AddressResponse(*s_addr[:2]).pack(), s_addr)
                    continue

                ipv4_mapped = IPv6Address(s_addr[0]).ipv4_mapped
                if ipv4_mapped:
                    addr = (str(ipv4_mapped), s_addr[1])
                else:
                    addr = s_addr[:2]

                if addr in NETWORK_BY_ADDR:
                    net = NETWORK_BY_ADDR[addr]
                    # Relay to all peers in the network. This is very inefficient for
                    # larger networks. A proper solution would be to run a separate
                    # UDP relay for every peer on a dedicated port. Then, outbound
                    # traffic from WireGuard would go to a different relay depending
                    # on the desired actual peer.
                    for peer in net.peers:
                        # at least don't relay back to peer
                        if addr != peer.addr4 and addr != peer.addr6:

                            if peer.addr6:
                                # Use IPv6 if possible
                                peer_addr = peer.addr6
                            else:
                                # Must translate IPv4 address to IPv4-mapped IPv6 address
                                peer_addr = ('::ffff:' + peer.addr4[0], peer.addr4[1])

                            log.debug('relay %s -> %s', addr, peer_addr)
                            sock.sendto(data, peer_addr)
                    continue

                log.warning('received unknown data from %s', addr)


def main():
    config = json.loads(Path('server_config.json').read_text(encoding='utf-8'))
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    relay = Relay()
    server = Server()

    Thread(target=relay.start, args=(config,)).start()
    Thread(target=server.start, args=(config,)).start()

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        log.info('shutting down sockets')
        for sock in SOCKETS:
            try:
                sock.shutdown(SHUT_RD)
            except OSError:
                pass
            sock.close()


if __name__ == '__main__':
    main()
