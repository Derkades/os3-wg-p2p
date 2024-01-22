import json
import logging
import os
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from threading import Thread

import messages
import udp
from messages import MAGIC, AddressResponse, PeerHello, PeerInfo, PeerList

log = logging.getLogger('client')


def create_tempfile(content: bytes, suffix: Optional[str] = None) -> str:
    fd, temp_path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, 'wb') as temp_file:
        temp_file.write(content)
    return temp_path


def run(command: list[str],
        check: bool = True,
        input: Optional[bytes] = None,
        capture_output: bool = False) -> bytes:
    log.debug('running command: %s', ' '.join(command))
    result = subprocess.run(command, check=check, capture_output=capture_output, input=input)
    if capture_output:
        return result.stdout.decode()


@dataclass
class WireGuard:
    privkey: str
    pubkey: str
    listen_port: int
    addr4: str
    addr6: str
    relay_endpoint: str
    if_name: Optional[str] = None
    use_nm = False

    def __enter__(self):
        if self.use_nm:
            config = f'''
            [Interface]
            ListenPort = {self.listen_port}
            PrivateKey = {self.privkey}
            Address = {self.addr4}/24, {self.addr6}/64
            MTU = 1380
            '''
            config_path = create_tempfile(config.encode(), suffix='.conf')
            self.if_name = Path(config_path).name.split('.')[0]
            run(['nmcli', 'connection', 'import', '--temporary', 'type', 'wireguard', 'file', config_path])
            os.unlink(config_path)
        else:
            privkey_path = create_tempfile(self.privkey.encode())
            self.if_name = Path(privkey_path).name.split('.')[0]  # convenient way to get random string
            # run(['ip', 'link', 'del', self.if_name], check=False)
            run(['ip', 'link', 'add', self.if_name, 'type', 'wireguard'])
            run(['wg', 'set', self.if_name, 'private-key', privkey_path, 'listen-port', str(self.listen_port)])
            run(['ip', 'address', 'add', self.addr4 + '/24', 'dev', self.if_name])
            run(['ip', 'address', 'add', self.addr6 + '/64', 'dev', self.if_name])
            run(['ip', 'link', 'set', 'mtu', '1380', 'up', 'dev', self.if_name])
            os.unlink(privkey_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.use_nm:
            run(['nmcli', 'connection', 'down', self.if_name])
            run(['nmcli', 'connection', 'delete', self.if_name])
        else:
            run(['ip', 'link', 'del', self.if_name])

    def list_peers(self) -> list[str]:
        return run(['wg', 'show', self.if_name, 'peers'], capture_output=True).splitlines()

    def update_peers(self, peers: list[PeerInfo]):
        current_pubkeys = self.list_peers()
        log.debug('current peers: %s', current_pubkeys)

        for peer in peers:
            if peer.pubkey == self.pubkey or peer.pubkey in current_pubkeys:
                continue

            # If multiple peers are added, they need to be added at the same time, because
            # UDP hole punching and relay fallback are time-sensitive.
            Thread(target=self.add_peer, args=(peer,)).start()

        # Remove local peers that are no longer known by the server
        active_pubkeys = {peer.pubkey for peer in peers}
        for pubkey in current_pubkeys:
            if pubkey not in active_pubkeys:
                log.info('removing peer: %s', pubkey)
                run(['wg', 'set', self.if_name, 'peer', pubkey, 'remove'])

    def add_peer(self, peer: PeerInfo):
        log.info('adding peer: %s', peer.pubkey)

        # UDP hole punching
        udp.send(b'', ('127.0.0.1', self.listen_port), (peer.host, peer.port))

        # Add peer with low keepalive
        endpoint = f'{peer.host}:{peer.port}'
        allowed_ips = f'{peer.vpn_addr4}/32, {peer.vpn_addr6}/128'
        run(['wg', 'set', self.if_name, 'peer', peer.pubkey, 'endpoint', endpoint, 'persistent-keepalive', '1', 'allowed-ips', allowed_ips])

        # Monitor RX bytes. The other end has also set persistent-keepalive=1, so we should see our
        # received bytes increase with 32 bytes every second
        rx_bytes = self.rx_bytes()
        time.sleep(10)
        new_rx_bytes = self.rx_bytes()
        if new_rx_bytes > rx_bytes + 32 * 5:
            log.debug('p2p connection appears to be working')
            # Keepalive can now be increased to 25 seconds
            run(['wg', 'set', self.if_name, 'peer', peer.pubkey, 'persistent-keepalive', '25'])
            return

        # Even if the two ends of a peer to peer connection decide differently on whether the
        # connection is working, they will still end up both using the same method, because
        # WireGuard updates its endpoint when it receives data from a different source address.

        log.debug('too little RX bytes, from %s to %s', rx_bytes, new_rx_bytes)
        # Set endpoint to relay server, also increase keepalive
        run(['wg', 'set', self.if_name, 'peer', peer.pubkey, 'endpoint', self.relay_endpoint, 'persistent-keepalive', '25'])


    def rx_bytes(self) -> int:
        return int(Path(f'/sys/class/net/{self.if_name}/statistics/rx_bytes').read_text(encoding='utf-8'))

    @staticmethod
    def gen_privkey():
        return run(['wg', 'genkey'], capture_output=True)[:-1]

    @staticmethod
    def gen_pubkey(privkey: str):
        return run(['wg', 'pubkey'], input=privkey.encode(), capture_output=True)[:-1]


def main():
    config = json.loads(Path('client_config.json').read_text(encoding='utf-8'))
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    privkey = WireGuard.gen_privkey()
    pubkey = WireGuard.gen_pubkey(privkey)
    relay_endpoint = f"{config['server_host']}:{config['server_port']}"

    log.debug('wireguard public key: %s', pubkey)

    # Send UDP packet to server to discover external address and port.
    # Also opens up NAT/firewall to receive UDP from relay server to WireGuard
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        log.info('sending hello to server: %s:%s', config['server_host'], config['server_port'])
        sock.sendto(MAGIC, (config['server_host'], config['server_port']))
        data = sock.recv(AddressResponse.SIZE)  # TODO time-out and retry
        addr_resp = AddressResponse.unpack(data)
        log.info('external address: %s:%s', addr_resp.host, addr_resp.port)
        # Remember source port before closing, must be reused for WireGuard
        source_port = sock.getsockname()[1]

    with WireGuard(privkey, pubkey, source_port, config['address4'], config['address6'], relay_endpoint) as wg:
        # Establish connection for management channel
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((config['server_host'], config['server_port']))

            # Send hello to server via management channel
            hello = PeerHello(config['uuid'], pubkey, config['address4'], config['address6'], addr_resp.host, addr_resp.port)
            sock.send(messages.pack(hello))

            while True:
                data = sock.recv(16384)
                if data == b'':
                    break

                peer_list: PeerList = messages.unpack(data)
                log.info('received %s peers from server', len(peer_list.peers))
                log.debug("peer list: %s", peer_list)
                wg.update_peers(peer_list.peers)


if __name__ == '__main__':
    main()
