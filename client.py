from dataclasses import dataclass
from ipaddress import IPv6Address
import json
import logging
import os
import time
from pathlib import Path
from socket import AF_INET, SHUT_RDWR, SOCK_DGRAM, SOCK_STREAM, socket, getaddrinfo
from threading import Event, Thread
import select
from typing import Optional
import sys

import messages
from messages import MAGIC, AddressResponse, PeerHello, PeerList
from wg import WGManager, get_wireguard

log = logging.getLogger('client')


@dataclass
class SourceAddrInfo:
    ext_addr: str
    ext_port: int
    local_port: int


def mgmt_thread(mgmt_sock: socket, config, pubkey: str, addr4: SourceAddrInfo, addr6: SourceAddrInfo, wg: WGManager):
    # Establish connection for management channel
    mgmt_sock.connect((config['server_host'], config['server_port']))

    # Send hello to server via management channel
    hello = PeerHello(config['uuid'],
                      pubkey,
                      (addr4.ext_addr, addr4.ext_port),
                      (addr6.ext_addr, addr6.ext_port),
                      config['address4'],
                      config['address6'])
    mgmt_sock.send(messages.pack(hello))

    while True:
        data = mgmt_sock.recv(16384)
        if data == b'':
            break

        peer_list: PeerList = messages.unpack(data)
        log.info('received %s peers from server', len(peer_list.peers))
        log.debug("peer list: %s", peer_list)
        wg.update_peers(peer_list.peers)

    log.debug('mgmt thread exits')


def get_addr_info(server_host: str, server_port: int):
    """
    Send UDP packet to server to discover external address and port.
    Also opens up NAT/firewall to receive UDP from relay server to WireGuard
    """
    inputs = []
    outputs = []

    for address in getaddrinfo(server_host, server_port, type=SOCK_DGRAM):
        log.debug('Creating socket using addrinfo %s', address)
        s_family, s_type, _s_proto, _s_canonname, s_addr = address
        sock = socket(s_family, s_type)
        sock.setblocking(0)
        sock.connect(s_addr)
        inputs.append(sock)
        outputs.append(sock)

    addr4: Optional[SourceAddrInfo] = None
    addr6: Optional[SourceAddrInfo] = None

    while len(inputs) > 0:
        log.debug('loop')
        readable, writable, exceptional = select.select(inputs, outputs, inputs, 2)

        for sock in readable:
            try:
                data = sock.recv(AddressResponse.SIZE)
                resp = AddressResponse.unpack(data)
                info = SourceAddrInfo(resp.host, resp.port, sock.getsockname()[1])
                if IPv6Address(resp.host).ipv4_mapped:
                    addr4 = info
                    log.debug('received IPv4 mapped response: %s', addr4)
                else:
                    addr6 = info
                    log.debug('received IPv6 AddressResponse: %s', addr6)
            except ConnectionRefusedError:
                log.debug('refused from %s', sock)

            sock.close()
            inputs.remove(sock)

        for sock in writable:
            log.debug('send magic')
            sock.send(MAGIC)
            outputs.remove(sock)

        for sock in exceptional:
            log.debug('exceptional: %s', sock)
            sock.close()
            inputs.remove(sock)

    return addr4, addr6


def main():
    config = json.loads(Path('client_config.json').read_text(encoding='utf-8'))
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    privkey = WGManager.gen_privkey()
    pubkey = WGManager.gen_pubkey(privkey)
    relay_endpoint = f"{config['server_host']}:{config['server_port']}"

    log.debug('wireguard public key: %s', pubkey)

    addr4, addr6 = get_addr_info(config['server_host'], config['server_port'])

    if not addr4:
        log.error('received no AddressResponse over IPv4, this is required!')
        sys.exit(1)

    mgmt_sock = socket(AF_INET, SOCK_STREAM)

    if_name = 'wg_p2p_' + os.urandom(2).hex()
    source_port = addr4.local_port  # TODO IPv4 assumed
    wg = get_wireguard(config['network_manager'], if_name, privkey, pubkey, source_port, config['address4'], config['address6'], relay_endpoint)

    def interface_up():
        log.info('interface is up, connecting to management channel')
        Thread(target=mgmt_thread, args=(mgmt_sock, config, pubkey, addr4, addr6, wg)).start()

    log.info('creating WireGuard interface')
    wg.create_interface(interface_up)

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        log.debug('close socket')
        mgmt_sock.shutdown(SHUT_RDWR)
        mgmt_sock.close()
        log.debug('remove interface')
        event = Event()
        wg.remove_interface(event.set)
        log.debug('waiting for remove_interface event')
        event.wait()


if __name__ == '__main__':
    main()
