import json
import logging
import socket
from dataclasses import dataclass
from threading import Thread
import time

import messages
from messages import (MAGIC_HEADER, AddressResponse, PeerHello, PeerInfo,
                      PeerList)

log = logging.getLogger('server')


def read_config():
    with open('server_config.json') as config_file:
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

def mgmt_client_thread(sock, addr):
    while True:
        data = sock.recv(16384)
        if data == b'':
            break

        log.debug('received PeerHello %s %s', data, addr)

        hello: PeerHello = messages.unpack(data)

        new_peer = Peer(sock, (hello.host, hello.port), hello.pubkey, hello.vpn_addr4, hello.vpn_addr6)

        log.debug('new peer: %s', new_peer)

        if hello.uuid in NETWORK_BY_UUID:
            log.info('joining peer onto existing network %s', hello.uuid)
            net = NETWORK_BY_UUID[hello.uuid]
            net.peers.append(new_peer)
        else:
            log.info('registered new network %s for peer %s', hello.uuid, addr)
            net = Network(hello.uuid, [new_peer])
            NETWORK_BY_UUID[hello.uuid] = net

        if hello.relay:
            NETWORK_BY_ADDR[(hello.host, hello.port)] = net

        time.sleep(2)

        log.info('broadcast updated peer list')
        peer_list = PeerList([PeerInfo(peer.wg_addr[0], peer.wg_addr[1], peer.pubkey, peer.vpn_addr4, peer.vpn_addr6) for peer in net.peers])
        peer_list_bytes = messages.pack(peer_list)
        broken_peers: list[Peer] = []
        for peer in net.peers:
            try:
                peer.mgmt_sock.send(peer_list_bytes)
            except BrokenPipeError:
                broken_peers.append(peer)

        for broken_peer in broken_peers:
            log.info('removing disconnected peer: %s', broken_peer.pubkey)
            net.peers.remove(broken_peer)


def mgmt_server_socket(config):
    bind_addr = ('0.0.0.0', config['server_port'])
    log.info('listening for TCP on %s', bind_addr)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(bind_addr)
        sock.listen()
        while True:
            sock2, addr = sock.accept()
            Thread(target=mgmt_client_thread, daemon=True, args=(sock2, addr)).start()


def udp_socket(config):
    bind_addr = ('0.0.0.0', config['server_port'])
    log.info('listening for UDP on %s', bind_addr)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(bind_addr)
        while True:
            data, addr = sock.recvfrom(1024)
            if data == MAGIC_HEADER:
                log.info('sending address response to %s', addr)
                sock.sendto(AddressResponse(addr[0], addr[1]).pack(), addr)
                continue

            if addr in NETWORK_BY_ADDR:
                # Relay to all peers in the network. This is very inefficient for
                # larger networks. A proper solution would be to run a separate
                # UDP relay for every peer on a dedicated port. Then, outbound
                # traffic from WireGuard would go to a different relay depending
                # on the desired actual peer.

                net = NETWORK_BY_ADDR[addr]
                for peer in net.peers:
                    log.debug('relay %s -> %s', addr, peer.wg_addr)
                    sock.sendto(data, peer.wg_addr)
                continue

            log.warning('received unknown data from %s', addr)


def main():
    config = read_config()
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    Thread(target=udp_socket, daemon=True, args=(config,)).start()
    mgmt_server_socket(config)


if __name__ == '__main__':
    main()
