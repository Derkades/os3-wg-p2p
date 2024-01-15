import socket
import stun
import time
import subprocess
import tempfile
import os
import json
from base64 import b64decode, b64encode
from connection import ConnectionRequest, ConnectionResponse, MAGIC_HEADER


def read_config():
    with open('config.json') as config_file:
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
AllowedIPs = {peer_addr}
PersistentKeepalive = 25
'''.encode()
        temp_config.write(wg_config)
    print(wg_config.decode())
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
    req = ConnectionRequest(do_relay, b64decode(config['pubkey']), uuid.encode())
    sock.sendto(MAGIC_HEADER + req.pack(), (config['relay_host'], config['relay_port']))
    print('Sent data to relay server, waiting for response')
    data = sock.recv(1024)
    resp = ConnectionResponse.unpack(data)
    print('Got response:', resp)
    peer_pubkey = b64encode(resp.pubkey).decode()

    # remember source port
    source_port = sock.getsockname()[1]
    sock.close()

    if do_relay:
        print('Using relay server')
        # Relay server is peer
        peer_ip = config['relay_host']
        peer_port = config['relay_port']
    else:
        print('Using UDP hole punch. Using STUN server to determine external address and port...')
        peer_ip = resp.addr.rstrip(b'\x00').decode()
        peer_port = resp.port

        nat_type, external_ip, external_port = \
            stun.get_ip_info(source_port=source_port,
                             stun_host='77.72.169.210')

        print('NAT type:', nat_type)
        print('External IP:', external_ip)
        print('External port:', external_port)

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
                        config['peer_address'],
                        f'{peer_ip}:{peer_port}')


if __name__ == '__main__':
    main()
