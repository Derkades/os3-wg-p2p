import json
import logging
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, SHUT_RDWR
import time
from pathlib import Path
from threading import Thread
import messages
from messages import MAGIC, AddressResponse, PeerHello, PeerList
from wg import get_wireguard, NMWGManager, WGManager

log = logging.getLogger('client')


def mgmt_thread(mgmt_sock: socket, config, pubkey: str, host: str, port: int, wg: WGManager):
    # Establish connection for management channel
    mgmt_sock.connect((config['server_host'], config['server_port']))

    # Send hello to server via management channel
    hello = PeerHello(config['uuid'], pubkey, config['address4'], config['address6'], host, port)
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


def main():
    config = json.loads(Path('client_config.json').read_text(encoding='utf-8'))
    logging.basicConfig()
    logging.getLogger().setLevel(config['log_level'])

    privkey = WGManager.gen_privkey()
    pubkey = WGManager.gen_pubkey(privkey)
    relay_endpoint = f"{config['server_host']}:{config['server_port']}"

    log.debug('wireguard public key: %s', pubkey)

    # Send UDP packet to server to discover external address and port.
    # Also opens up NAT/firewall to receive UDP from relay server to WireGuard
    with socket(AF_INET, SOCK_DGRAM) as sock:
        log.info('sending hello to server: %s:%s', config['server_host'], config['server_port'])
        sock.sendto(MAGIC, (config['server_host'], config['server_port']))
        data = sock.recv(AddressResponse.SIZE)  # TODO time-out and retry
        addr_resp = AddressResponse.unpack(data)
        log.info('external address: %s:%s', addr_resp.host, addr_resp.port)
        # Remember source port before closing, must be reused for WireGuard
        source_port = sock.getsockname()[1]

    mgmt_sock = socket(AF_INET, SOCK_STREAM)

    wg = get_wireguard(privkey, pubkey, source_port, config['address4'], config['address6'], relay_endpoint)
    nm = isinstance(wg, NMWGManager)
    wg.create_interface()

    Thread(target=mgmt_thread, args=(mgmt_sock, config, pubkey, addr_resp.host, addr_resp.port, wg)).start()

    try:
        if nm:
            from gi.repository import GLib
            loop = GLib.MainLoop()
            Thread(target=loop.run).start()
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        log.debug('close socket')
        mgmt_sock.shutdown(SHUT_RDWR)
        mgmt_sock.close()
        log.debug('remove interface')
        wg.remove_interface()
        if nm:
            time.sleep(1)  # TODO use callback on remove_interface() instead of sleeping
            log.debug('quit GLib loop')
            loop.quit()


if __name__ == '__main__':
    main()
