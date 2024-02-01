import json
import logging
import os
import select
import sys
import time
from ipaddress import IPv6Address
from pathlib import Path
from socket import SHUT_RDWR, SOCK_DGRAM, SOCK_STREAM, getaddrinfo, socket
from threading import Event, Thread
from typing import Optional
import random

import messages
from messages import MAGIC, AddressResponse, PeerHello, PeerList
from wg import WGManager, get_wireguard

log = logging.getLogger('client')


def mgmt_thread(mgmt_sock: socket, config, pubkey: str, addr4: tuple[str, int], addr6: tuple[str, int], wg: WGManager):
    # Send hello to server via management channel
    hello = PeerHello(config['uuid'],
                      pubkey,
                      config['address4'],
                      config['address6'],
                      addr4,
                      addr6)
    log.debug('sending hello: %s', hello)
    mgmt_sock.send(messages.pack(hello))

    while True:
        data = mgmt_sock.recv(16384)
        if data == b'':
            break

        peer_list: PeerList = messages.unpack(data)
        log.debug('received %s peers from server', len(peer_list.peers))
        log.debug("peer list: %s", peer_list)
        wg.update_peers(peer_list.peers)

    log.debug('mgmt thread exits')


def get_addr_info(server_host: str, server_port: int, source_port: int) -> tuple[tuple[str, int], tuple[str, int]]:
    """
    Send UDP packet to server to discover external address and port.
    Also opens up NAT/firewall to receive UDP from relay server to WireGuard
    """
    addr4: Optional[tuple[str, int]] = None
    addr6: Optional[tuple[str, int]] = None

    for address in getaddrinfo(server_host, server_port, type=SOCK_DGRAM):
        s_family, s_type, _s_proto, _s_canonname, s_addr = address

        with socket(s_family, s_type) as sock:
            log.debug('connecting to %s with source port %s', s_addr, source_port)
            sock.bind(('', source_port))
            sock.connect(s_addr)
            sock.send(MAGIC)
            readable, _writable, _exceptional = select.select([sock], [], [], 2)
            if not readable:
                log.debug('no response from server')
                continue
            data = readable[0].recv(AddressResponse.SIZE)
            resp = AddressResponse.unpack(data)
            ipv4_mapped = IPv6Address(resp.host).ipv4_mapped
            if ipv4_mapped:
                addr4 = (str(ipv4_mapped), resp.port)
            else:
                addr6 = (resp.host, resp.port)

    return addr4, addr6


def main():
    config = json.loads(Path('client_config.json').read_text(encoding='utf-8'))
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    privkey = WGManager.gen_privkey()
    pubkey = WGManager.gen_pubkey(privkey)
    relay_endpoint = f"{config['server_host']}:{config['server_port']}"

    log.debug('wireguard public key: %s', pubkey)

    log.info('retrieving address information')

    listen_port = random.randint(2**15, 2**16)
    addr4, addr6 = get_addr_info(config['server_host'], config['server_port'], listen_port)

    if not addr4 and not addr6:
        log.error('could not discover external address')
        sys.exit(1)

    log.info('address info IPv4: %s', addr4)
    log.info('address info IPv6: %s', addr6)

    addresses = getaddrinfo(config['server_host'], config['server_port'], type=SOCK_STREAM)
    for s_family, s_type, _s_proto, _s_canonname, s_addr in addresses:
        # Establish connection for management channel
        mgmt_sock = socket(s_family, s_type)
        mgmt_sock.connect(s_addr)
        log.info('connected to management server: [%s]:%s', s_addr[0], s_addr[1])
        break
    else:
        log.error('cannot resolve server host: %s', config['server_host'])
        sys.exit(1)

    if_name = 'wg_p2p_' + os.urandom(2).hex()

    wg = get_wireguard(config['network_manager'], if_name, privkey, pubkey,
                       listen_port, addr4 is not None, addr6 is not None,
                       config['address4'], config['address6'],
                       relay_endpoint)

    def interface_up():
        Thread(target=mgmt_thread, args=(mgmt_sock, config, pubkey, addr4, addr6, wg)).start()

    log.info('creating WireGuard interface')
    wg.create_interface(interface_up)

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        log.info('exiting')
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
