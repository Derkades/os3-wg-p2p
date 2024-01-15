import json
import os
import socket
import subprocess
import tempfile
import time
from base64 import b64decode, b64encode

from connection import MAGIC_HEADER, ConnectionRequest, ConnectionResponse


def read_config():
    with open('client_config.json') as config_file:
        return json.load(config_file)


def create_wg_interface(if_name: str, privkey: str, port: int, addr: str, peer_pubkey: str, peer_addr: str, peer_endpoint: str):
    fd, temp_path = tempfile.mkstemp()

    with os.fdopen(fd, 'wb') as temp_config:
        wg_config = \
        f'''[Interface]
ListenPort = {port}
PrivateKey = {privkey}

[Peer]
Endpoint = {peer_endpoint}
PublicKey = {peer_pubkey}
AllowedIPs = {peer_addr}/32
PersistentKeepalive = 25
'''.encode()
        temp_config.write(wg_config)
    print(wg_config.decode())
    print('delete old interface')
    subprocess.call(['sudo', 'ip', 'link', 'del', if_name])
    print('create interface')
    subprocess.check_call(['sudo', 'ip', 'link', 'add', if_name, 'type', 'wireguard'])
    print('setconf')
    subprocess.check_call(['sudo', 'wg', 'setconf', if_name, temp_path])
    print('add address')
    subprocess.check_call(['sudo', 'ip', 'address', 'add', addr, 'dev', if_name])
    print('set mtu')
    subprocess.check_call(['sudo', 'ip', 'link', 'set', 'mtu', '1380', 'up', 'dev', if_name])


def main():
    # TODO also exchange VPN address
    config = read_config()

    uuid = input('Enter unique id:')
    do_relay = bool(int(input('Use relay, 1 or 0?')))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    req = ConnectionRequest(do_relay, b64decode(config['pubkey']), uuid.encode(), config['address'].split('/')[0].encode())
    sock.sendto(MAGIC_HEADER + req.pack(), (config['server_host'], config['server_port']))
    print('Sent data to relay server, waiting for response')
    data = sock.recv(1024)
    resp = ConnectionResponse.unpack(data)
    print('Got response:', resp)
    peer_pubkey = b64encode(resp.pubkey).decode()
    peer_address = resp.vpn_addr.rstrip(b'\x00').decode()

    # remember source port
    source_port = sock.getsockname()[1]
    sock.close()

    if do_relay:
        print('Using relay server')
        # Relay server is peer
        peer_ip = config['server_host']
        peer_port = config['server_port']
    else:
        print('Using UDP hole punch')
        peer_ip = resp.addr.rstrip(b'\x00').decode()
        peer_port = resp.port

        # Datagram to create entry in NAT table
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.bind(('', source_port))
        sock2.sendto(b'', (peer_ip, peer_port))
        sock2.close()

        # Wait for UDP packet to be sent in both directions
        time.sleep(2)

    create_wg_interface(config['interface'],
                        config['privkey'],
                        source_port,
                        config['address'],
                        peer_pubkey,
                        peer_address,
                        f'{peer_ip}:{peer_port}')


if __name__ == '__main__':
    main()
