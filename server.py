import json
import logging
import socket
from dataclasses import dataclass
from threading import Thread
from multiprocessing.pool import ThreadPool
import time
import sys

import messages
from messages import (MAGIC, AddressResponse, PeerHello, PeerInfo,
                      PeerList)

log = logging.getLogger('server')


def read_config():
    with open('server_config.json', encoding='utf-8') as config_file:
        return json.load(config_file)


@dataclass
class Peer:
    """Device (a WireGuard interface) in a network"""
    mgmt_sock: socket.socket
    wg_addr: tuple[str, int]
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
SOCKETS: set[socket.socket] = set()
POOL = ThreadPool(16)


def broadcast_peers(peers):
    log.info('broadcast updated peer list to %s peers', len(peers))
    peer_list = PeerList([PeerInfo(peer.wg_addr[0], peer.wg_addr[1], peer.pubkey, peer.vpn_addr4, peer.vpn_addr6) for peer in peers])
    peer_list_bytes = messages.pack(peer_list)
    broken_peers: list[Peer] = []

    def send_peer_list(peer):
        try:
            peer.mgmt_sock.send(peer_list_bytes)
        except BrokenPipeError:
            broken_peers.append(peer)

    POOL.map(send_peer_list, peers)

    for broken_peer in broken_peers:
        log.info('removing disconnected peer: %s', broken_peer.pubkey)
        peers.remove(broken_peer)
        SOCKETS.remove(broken_peer)


def mgmt_client_thread(sock):
    while True:
        data = sock.recv(16384)
        if data == b'':
            break

        log.debug('received PeerHello %s', data)

        hello: PeerHello = messages.unpack(data)
        new_peer = Peer(sock, (hello.host, hello.port), hello.pubkey, hello.vpn_addr4, hello.vpn_addr6)

        log.debug('new peer: %s', new_peer)

        if hello.uuid in NETWORK_BY_UUID:
            log.info('joining peer %s onto existing network %s', hello.pubkey, hello.uuid)
            net = NETWORK_BY_UUID[hello.uuid]
            net.peers.append(new_peer)
        else:
            log.info('registered new network %s for peer %s', hello.uuid, hello.pubkey)
            net = Network(hello.uuid, [new_peer])
            NETWORK_BY_UUID[hello.uuid] = net

        NETWORK_BY_ADDR[(hello.host, hello.port)] = net

        time.sleep(1) # wait for client to be ready to receive management data

        broadcast_peers(net.peers)


def mgmt_server_socket(config):
    bind_addr = ('0.0.0.0', config['server_port'])
    log.info('listening for TCP on %s', bind_addr)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        SOCKETS.add(sock)
        sock.bind(bind_addr)
        sock.listen()
        while True:
            try:
                client_sock, _client_addr = sock.accept()
            except OSError:
                break
            SOCKETS.add(client_sock)

            POOL.apply_async(mgmt_client_thread, args=(client_sock,))

    log.debug('mgmt exit')


def udp_socket(config):
    bind_addr = ('0.0.0.0', config['server_port'])
    log.info('listening for UDP on %s', bind_addr)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        SOCKETS.add(sock)
        sock.bind(bind_addr)
        while True:
            data, addr = sock.recvfrom(1024)
            if data == b'':
                log.debug('udp socket is dead')
                break

            if data == MAGIC:
                log.info('sending address response to %s', addr)
                sock.sendto(AddressResponse(addr[0], addr[1]).pack(), addr)
                continue

            if addr in NETWORK_BY_ADDR:
                net = NETWORK_BY_ADDR[addr]
                # Relay to all peers in the network. This is very inefficient for
                # larger networks. A proper solution would be to run a separate
                # UDP relay for every peer on a dedicated port. Then, outbound
                # traffic from WireGuard would go to a different relay depending
                # on the desired actual peer.
                for peer in net.peers:
                    if addr != peer.wg_addr:
                        log.debug('relay %s -> %s', addr, peer.wg_addr)
                        sock.sendto(data, peer.wg_addr)
                continue

            log.warning('received unknown data from %s', addr)


def main():
    config = read_config()
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    Thread(target=udp_socket, args=(config,)).start()
    Thread(target=mgmt_server_socket, args=(config,)).start()

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        log.info('shutting down sockets')
        for sock in SOCKETS:
            try:
                sock.shutdown(socket.SHUT_RD)
            except OSError:
                pass
            sock.close()

        POOL.terminate()


if __name__ == '__main__':
    main()
