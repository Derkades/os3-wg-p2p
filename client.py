import socket
import stun
import time
import subprocess
import tempfile
import os
import json


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
PersistentKeepalive = 1
'''.encode()
        temp_config.write(wg_config)

    print('create interface')
    subprocess.check_call(['sudo', 'ip', 'link', 'add', if_name, 'type', 'wireguard'])
    print('setconf')
    subprocess.check_call(['sudo', 'wg', 'setconf', if_name, temp_path])
    print('add address')
    subprocess.check_call(['sudo', 'ip', 'address', 'add', addr, 'dev', if_name])
    print('set mtu')
    subprocess.check_call(['sudo', 'ip', 'link', 'set', 'mtu', '1380', 'up', 'dev', if_name])


def send_udp(source_port: int, dest_host: str, dest_port: int, message: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', source_port))
    sock.sendto(message, (dest_host, dest_port))
    sock.close()


def send_relay_magic(source_port: int, uuid: str, relay_host: str, relay_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', source_port))
    sock.sendto(b'magic' + uuid.encode(), (relay_host, relay_port))
    sock.close()


def main():
    config = read_config()

    uuid = input('Enter relay uuid, or press enter perform UDP hole punching:')

    if uuid == '':
        nat_type, external_ip, external_port = \
            stun.get_ip_info(source_port=config['source_port'],
                             stun_host='77.72.169.210')

        print('NAT type (potentially incorrect):', nat_type)
        print('External IP:', external_ip)
        print('External port:', external_port)

        other_ip = config['other_ip']
        other_port = int(input('enter other port (press enter in sync):'))

        send_udp(config['source_port'], other_ip, other_port, b'')

        # Wait for UDP packet to be sent in both directions
        time.sleep(2)
    else:
        other_ip = config['relay_host']
        other_port = config['relay_port']
        print('Sending relay magic')
        send_relay_magic(config['source_port'], uuid, config['relay_host'], config['relay_port'])
        time.sleep(2)

    create_wg_interface(config['interface'],
                        config['private_key'],
                        config['source_port'],
                        config['address'],
                        config['peer_pubkey'],
                        config['peer_address'],
                        other_ip + ':' + str(other_port))


if __name__ == '__main__':
    main()
