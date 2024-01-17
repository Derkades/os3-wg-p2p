import json
import logging
import os
import socket
import subprocess
import tempfile
import time

import messages
import udp
from messages import (MAGIC_HEADER, AddressResponse, PeerHello, PeerInfo,
                      PeerList)

log = logging.getLogger('client')


def read_config():
    with open('client_config.json', encoding='utf-8') as config_file:
        return json.load(config_file)


def create_tempfile(content: bytes) -> str:
    fd, temp_path = tempfile.mkstemp()
    with os.fdopen(fd, 'wb') as temp_file:
        temp_file.write(content)
    return temp_path


def run(command: list[str], check=True, input=None, capture_output=False) -> bytes:
    log.debug('running command: %s', ' '.join(command))
    result = subprocess.run(command, check=check, capture_output=capture_output, input=input)
    if capture_output:
        return result.stdout.decode()


def wg_genkey():
    return run(['wg', 'genkey'], capture_output=True)[:-1]


def wg_pubkey(privkey: str):
    return run(['wg', 'pubkey'], input=privkey.encode(), capture_output=True)[:-1]


def wg_create_interface(if_name: str, privkey: str, listen_port: int, addr4: str, addr6: str):
    privkey_path = create_tempfile(privkey.encode())
    run(['ip', 'link', 'del', if_name], check=False)
    run(['ip', 'link', 'add', if_name, 'type', 'wireguard'])
    run(['wg', 'set', if_name, 'private-key', privkey_path, 'listen-port', str(listen_port)])
    run(['ip', 'address', 'add', addr4 + '/24', 'dev', if_name])
    run(['ip', 'address', 'add', addr6 + '/64', 'dev', if_name])
    run(['ip', 'link', 'set', 'mtu', '1380', 'up', 'dev', if_name])
    os.unlink(privkey_path)


def wg_update_peers(if_name: str, peers: list[PeerInfo], relay_host: str, relay_port: int, use_relay: bool, source_port: int):
    # TODO remove peers from interface that are not in the peers list
    for peer in peers:
        if use_relay:
            host = relay_host
            port = relay_port
        else:
            host = peer.host
            port = peer.port
            # TODO hole punching for new peer is needed
            # but how to do that without restarting WireGuard? raw sockets?
            # Datagram to create entry in NAT table
            udp.send(b'', ('127.0.0.1', source_port), (host, port))
            # with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            #     sock.bind(('', source_port))
            #     sock.sendto(b'', (host, port))
            # Wait for UDP packet to be sent in both directions
            time.sleep(1)
        run(['wg', 'set', if_name, 'peer', peer.pubkey, 'endpoint', f'{host}:{port}', 'persistent-keepalive', '25', 'allowed-ips', f'{peer.vpn_addr4}/32, {peer.vpn_addr6}/128'])


def main():
    config = read_config()
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    # use_relay = bool(int(input('use relay, 1 or 0? ')))
    use_relay = False

    privkey = wg_genkey()
    pubkey = wg_pubkey(privkey)

    log.debug('wireguard public key: %s', pubkey)

    # Send UDP packet to server to discover external address and port.
    # Also opens up NAT/firewall to receive UDP from relay server to WireGuard
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(MAGIC_HEADER, (config['server_host'], config['server_port']))
        data = sock.recv(AddressResponse.SIZE)
        addr_resp = AddressResponse.unpack(data)
        log.debug('got response: %s', addr_resp)
        # Remember source port before closing, must be reused for WireGuard
        source_port = sock.getsockname()[1]

    wg_create_interface(config['interface'], privkey, source_port, config['address4'], config['address6'])

    # Establish connection for management channel
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((config['server_host'], config['server_port']))

        # Send hello to server via management channel
        hello = PeerHello(use_relay, config['uuid'], pubkey, config['address4'], config['address6'], addr_resp.host, addr_resp.port)
        sock.send(messages.pack(hello))

        while True:
            data = sock.recv(16384)
            if data == b'':
                break

            peer_list: PeerList = messages.unpack(data)
            log.debug("peer list: %s", peer_list)
            wg_update_peers(config['interface'], peer_list.peers, config['server_host'], config['server_port'], use_relay, source_port)

if __name__ == '__main__':
    main()
