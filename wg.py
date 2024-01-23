from dataclasses import dataclass
import logging
import os
from pathlib import Path
import socket
import tempfile
from threading import Thread
import time
from typing import Optional
import subprocess
import uuid
import udp
from abc import ABC, abstractmethod
from messages import PeerInfo

FORCE_DISABLE_NM = True

try:
    if FORCE_DISABLE_NM:
        NM = None
    else:
        import gi
        gi.require_version("NM", "1.0")
        from gi.repository import NM, GLib  # type: ignore
        print('Using NetworkManager')
except (ImportError, ValueError):
    print('NetworkManager not available, root access will be required.')
    NM = None

log = logging.getLogger(__name__)

def create_tempfile(content: bytes, suffix: Optional[str] = None) -> str:
    fd, temp_path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, 'wb') as temp_file:
        temp_file.write(content)
    return temp_path


def run(command: list[str],
        check: bool = True,
        stdin: Optional[bytes] = None,
        capture_output: bool = False) -> Optional[bytes]:
    log.debug('running command: %s', ' '.join(command))
    result = subprocess.run(command, check=check, capture_output=capture_output, input=stdin)
    return result.stdout.decode() if capture_output else None

@dataclass
class WGManager(ABC):
    privkey: str
    pubkey: str
    listen_port: int
    addr4: str
    addr6: str
    relay_endpoint: str
    mtu: int = 1380

    @abstractmethod
    def create_interface(self) -> None:
        pass

    @abstractmethod
    def remove_interface(self) -> None:
        pass

    @abstractmethod
    def list_peers(self) -> list[str]:
        pass

    @abstractmethod
    def add_peer(self, pubkey: str, endpoint: str, keepalive: int, allowed_ips: list[str]) -> None:
        pass

    @abstractmethod
    def remove_peer(self, pubkey: str) -> None:
        pass

    @abstractmethod
    def update_peer_endpoint(self, pubkey: str, endpoint: str) -> None:
        pass

    @abstractmethod
    def update_peer_keepalive(self, pubkey: str, keepalive: int) -> None:
        pass

    def update_peers(self, peers: list[PeerInfo]):
        current_pubkeys = self.list_peers()
        log.debug('current peers: %s', current_pubkeys)

        for peer in peers:
            if peer.pubkey == self.pubkey or peer.pubkey in current_pubkeys:
                continue

            # If multiple peers are added, they need to be added at the same time, because
            # UDP hole punching and relay fallback are time-sensitive.
            Thread(target=self.set_up_peer_connection, args=(peer,)).start()

        # Remove local peers that are no longer known by the server
        active_pubkeys = {peer.pubkey for peer in peers}
        for pubkey in current_pubkeys:
            if pubkey not in active_pubkeys:
                log.info('removing peer: %s', pubkey)
                self.remove_peer(pubkey)

    def set_up_peer_connection(self, peer: PeerInfo):
        log.info('adding peer: %s', peer.pubkey)

        # UDP hole punching
        udp.send(b'', ('127.0.0.1', self.listen_port), (peer.host, peer.port))

        # Add peer with low keepalive
        endpoint = f'{peer.host}:{peer.port}'
        allowed_ips = ['{peer.vpn_addr4}/32', f'{peer.vpn_addr6}/128']
        self.add_peer(peer.pubkey, endpoint, 1, allowed_ips)

        # Monitor RX bytes. The other end has also set persistent-keepalive=1, so we should see our
        # received bytes increase with 32 bytes every second
        rx_bytes = self.rx_bytes()
        time.sleep(10)
        new_rx_bytes = self.rx_bytes()
        if new_rx_bytes > rx_bytes + 32 * 5:
            log.debug('p2p connection appears to be working')
            # Keepalive can now be increased to 25 seconds
            self.update_peer_keepalive(peer.pubkey, 25)
            return

        # Even if the two ends of a peer to peer connection decide differently on whether the
        # connection is working, they will still end up both using the same method, because
        # WireGuard updates its endpoint when it receives data from a different source address.

        log.debug('too little RX bytes, from %s to %s', rx_bytes, new_rx_bytes)
        log.info('P2P connection to %s failed, falling back to relay server', peer.pubkey)
        # Set endpoint to relay server, also increase keepalive
        self.update_peer_endpoint(peer.pubkey, self.relay_endpoint)
        self.update_peer_keepalive(peer.pubkey, 25)

    def rx_bytes(self) -> int:
        path = Path('/sys/class/net') / self.if_name / 'statistics' / 'rx_bytes'
        return path.read_text(encoding='utf-8')

    @staticmethod
    def gen_privkey():
        return run(['wg', 'genkey'], capture_output=True)[:-1]

    @staticmethod
    def gen_pubkey(privkey: str):
        return run(['wg', 'pubkey'], stdin=privkey.encode(), capture_output=True)[:-1]


class NMWGManager(WGManager):
    nm_uuid: Optional[str] = None

    def create_interface(self):
        self.nm_uuid = str(uuid.uuid4())
        s_con = NM.SettingConnection.new()
        s_con.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, 'VPN')
        s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'wireguard')
        s_con.set_property(NM.SETTING_CONNECTION_UUID, self.nm_uuid)
        s_con.set_property(NM.SETTING_CONNECTION_ID, self.nm_uuid[:6])

        s_ip4 = NM.SettingIP4Config.new()
        s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, 'manual')
        s_ip4.add_address(NM.IPAddress(socket.AF_INET, self.addr4, 24))

        s_wg = NM.SettingWireGuard.new()
        s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY, self.privkey)
        s_wg.set_property(NM.SETTING_WIREGUARD_MTU, self.mtu)

        profile = NM.SimpleConnection.new()
        for s in (s_con, s_ip4, s_wg):
            profile.add_setting(s)

        nm = NM.Client.new(None)

        def add_callback(nm2, result):
            log.debug('add_callback')
            nm2.add_connection_finish(result)

        def add():
            log.debug('add')
            nm.add_connection_async(connection=profile, save_to_disk=False, callback=add_callback)

        log.debug('idle_add')
        GLib.idle_add(add)

    def remove_interface(self):
        def delete_callback(a, res):
            a.delete_finish(res)

        def disconnect_callback(a, res, nm):
            a.disconnect_finish(res)
            con = nm.get_connection_by_uuid(self.nm_uuid)
            con.delete_async(callback=delete_callback)

        def disconnect():
            nm = NM.Client.new(None)
            for device in nm.get_all_devices():
                if device.get_type_description() == "wireguard" \
                    and self.nm_uuid in {conn.get_uuid() for conn in device.get_available_connections()}:
                    break
            else:
                log.warning('found no WireGuard device to remove')
                return

            device.disconnect_async(callback=disconnect_callback, user_data=nm)

        GLib.idle_add(disconnect)

    def list_peers(self):
        return []  # TODO

    def add_peer(self, pubkey: str, endpoint: str, keepalive: int, allowed_ips: list[str]) -> None:
        pass

    def remove_peer(self, pubkey: str) -> None:
        pass

    def update_peer_endpoint(self, pubkey: str, endpoint: str) -> None:
        pass

    def update_peer_keepalive(self, pubkey: str, keepalive: int) -> None:
        pass


class WGToolsWGManager(WGManager):
    if_name: Optional[str] = None

    def create_interface(self):
        self.if_name = os.urandom(4).hex()
        privkey_path = create_tempfile(self.privkey.encode())
        run(['ip', 'link', 'add', self.if_name, 'type', 'wireguard'])
        run(['wg', 'set', self.if_name, 'private-key', privkey_path, 'listen-port', str(self.listen_port)])
        run(['ip', 'address', 'add', self.addr4 + '/24', 'dev', self.if_name])
        run(['ip', 'address', 'add', self.addr6 + '/64', 'dev', self.if_name])
        run(['ip', 'link', 'set', 'mtu', str(self.mtu), 'up', 'dev', self.if_name])
        os.unlink(privkey_path)

    def remove_interface(self):
        run(['ip', 'link', 'del', self.if_name])

    def list_peers(self) -> list[str]:
        return run(['wg', 'show', self.if_name, 'peers'], capture_output=True).splitlines()

    def add_peer(self, pubkey: str, endpoint: str, keepalive: int, allowed_ips: list[str]) -> None:
        run(['wg', 'set', self.if_name,
             'peer', pubkey,
             'endpoint', endpoint,
             'persistent-keepalive', str(keepalive),
             'allowed-ips', ', '.join(allowed_ips)])

    def remove_peer(self, pubkey: str) -> None:
        run(['wg', 'set', self.if_name, 'peer', pubkey, 'remove'])

    def update_peer_endpoint(self, pubkey: str, endpoint: str) -> None:
        run(['wg', 'set', self.if_name, 'peer', pubkey, 'endpoint', endpoint])

    def update_peer_keepalive(self, pubkey: str, keepalive: int) -> None:
        run(['wg', 'set', self.if_name, 'peer', pubkey, 'persistent-keepalive', str(keepalive)])


def get_wireguard(*args) -> WGManager:
    if NM:
        return NMWGManager(*args)
    else:
        return WGToolsWGManager(*args)
