import json
import logging
import os
import select
import sys
import time
from dataclasses import dataclass
from ipaddress import IPv6Address
from pathlib import Path
from socket import SHUT_RDWR, SOCK_DGRAM, SOCK_STREAM, getaddrinfo, socket
from threading import Event, Thread
from typing import Optional

import messages
from messages import MAGIC, AddressResponse, PeerHello, PeerList
from wg import WGManager, get_wireguard

log = logging.getLogger('client')


@dataclass
class SourceAddrInfo:
    ext_addr: tuple[str, int]
    local_port: int


def mgmt_thread(mgmt_sock: socket, config, pubkey: str, addr4: Optional[SourceAddrInfo], addr6: Optional[SourceAddrInfo], wg: WGManager):
    # Send hello to server via management channel
    hello = PeerHello(config['uuid'],
                      pubkey,
                      config['address4'],
                      config['address6'],
                      addr4.ext_addr if addr4 else None,
                      addr6.ext_addr if addr6 else None)
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


def get_addr_info(server_host: str, server_port: int):
    """
    Send UDP packet to server to discover external address and port.
    Also opens up NAT/firewall to receive UDP from relay server to WireGuard
    """
    inputs = []
    outputs = []

    for address in getaddrinfo(server_host, server_port, type=SOCK_DGRAM):
        s_family, s_type, _s_proto, _s_canonname, s_addr = address
        sock = socket(s_family, s_type)
        sock.setblocking(0)
        sock.connect(s_addr)
        inputs.append(sock)
        outputs.append(sock)

    addr4: Optional[SourceAddrInfo] = None
    addr6: Optional[SourceAddrInfo] = None

    while len(inputs) > 0:
        readable, writable, exceptional = select.select(inputs, outputs, inputs, 2)

        for sock in readable:
            try:
                data = sock.recv(AddressResponse.SIZE)
                resp = AddressResponse.unpack(data)
                local_port = sock.getsockname()[1]
                ipv4_mapped = IPv6Address(resp.host).ipv4_mapped
                if ipv4_mapped:
                    addr4 = SourceAddrInfo((str(ipv4_mapped), resp.port), local_port)
                else:
                    addr6 = SourceAddrInfo((resp.host, resp.port), local_port)
            except ConnectionRefusedError:
                log.debug('refused from %s', sock)

            sock.close()
            inputs.remove(sock)

        for sock in writable:
            log.debug('sending magic to %s', sock.getpeername())
            sock.send(MAGIC)
            outputs.remove(sock)

        for sock in exceptional:
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

    log.info('retrieving address information')

    addr4, addr6 = get_addr_info(config['server_host'], config['server_port'])

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
    # either IPv4 OR IPv6, cannot do both without relay
    if addr4:
        # connect to IPv4-only hosts and dual stack hosts directly, IPv6-only hosts via relay
        listen_port = addr4.local_port
        ipv6 = False
    elif addr6:
        # connect to IPv6-only hosts, dual stack and IPv6-only hosts via relay
        listen_port = addr6.local_port
        ipv6 = True
    else:
        log.error('could not discover external address')
        sys.exit(1)

    wg = get_wireguard(config['network_manager'], if_name, privkey, pubkey, listen_port, ipv6, config['address4'], config['address6'], relay_endpoint)

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
