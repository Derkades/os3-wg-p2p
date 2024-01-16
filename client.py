import json
import os
import socket
import subprocess
import tempfile
import time

from connection import MAGIC_HEADER, ConnectionRequest, ConnectionResponse


def read_config():
    with open('client_config.json', encoding='utf-8') as config_file:
        return json.load(config_file)


def wg_genkey():
    return subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout.decode()


def wg_pubkey(privkey: str):
    return subprocess.run(['wg', 'pubkey'], input=privkey.encode(), check=True, capture_output=True).stdout.decode()


def create_wg_interface(if_name: str, privkey: str, port: int, addr4: str, addr6: str,
                        peer_pubkey: str, peer_addr4: str, peer_addr6: str, peer_endpoint: str):
    fd, temp_path = tempfile.mkstemp()

    with os.fdopen(fd, 'wb') as temp_config:
        wg_config = \
        f'''[Interface]
ListenPort = {port}
PrivateKey = {privkey}

[Peer]
Endpoint = {peer_endpoint}
PublicKey = {peer_pubkey}
AllowedIPs = {peer_addr4}/32, {peer_addr6}/128
PersistentKeepalive = 25
'''.encode()
        temp_config.write(wg_config)
    print(wg_config.decode())
    print('delete old interface')
    subprocess.call(['sudo', 'ip', 'link', 'del', if_name])
    print('create and configure new interface')
    subprocess.check_call(['sudo', 'ip', 'link', 'add', if_name, 'type', 'wireguard'])
    subprocess.check_call(['sudo', 'wg', 'setconf', if_name, temp_path])
    subprocess.check_call(['sudo', 'ip', 'address', 'add', addr4 + '/24', 'dev', if_name])
    subprocess.check_call(['sudo', 'ip', 'address', 'add', addr6 + '/64', 'dev', if_name])
    subprocess.check_call(['sudo', 'ip', 'link', 'set', 'mtu', '1380', 'up', 'dev', if_name])


def main():
    config = read_config()
    do_relay = bool(int(input('Use relay, 1 or 0?')))

    privkey = wg_genkey()
    pubkey = wg_pubkey(privkey)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        req = ConnectionRequest(do_relay, pubkey, config['uuid'], config['address4'], config['address6'])
        sock.sendto(MAGIC_HEADER + req.pack(), (config['server_host'], config['server_port']))
        print('Sent data to relay server, waiting for response')
        data = sock.recv(1024)
        resp = ConnectionResponse.unpack(data)
        print('Got response:', resp)

        # remember source port before closing
        source_port = sock.getsockname()[1]

    if do_relay:
        print('Using relay server')
        # Relay server is peer
        peer_host = config['server_host']
        peer_port = config['server_port']
    else:
        print('Using UDP hole punch')
        peer_host = resp.peer_host
        peer_port = resp.peer_port

        # Datagram to create entry in NAT table
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock2:
            sock2.bind(('', source_port))
            sock2.sendto(b'', (peer_host, peer_port))

        # Wait for UDP packet to be sent in both directions
        time.sleep(2)

    create_wg_interface(config['interface'],
                        privkey,
                        source_port,
                        config['address4'],
                        config['address6'],
                        resp.peer_pubkey,
                        resp.peer_vpn_addr4,
                        resp.peer_vpn_addr6,
                        f'{peer_host}:{peer_port}')


if __name__ == '__main__':
    main()
