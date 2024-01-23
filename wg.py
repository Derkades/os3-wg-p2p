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
    if_name: str
    privkey: str
    pubkey: str
    listen_port: int
    addr4: str
    addr6: str
    relay_endpoint: str
    mtu: int = 1380

    @abstractmethod
    def create_interface(self, callback) -> None:
        pass

    @abstractmethod
    def remove_interface(self, callback) -> None:
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
    def update_peer(self, pubkey: str, endpoint: str, keepalive: int) -> None:
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
        allowed_ips = [f'{peer.vpn_addr4}/32', f'{peer.vpn_addr6}/128']
        self.add_peer(peer.pubkey, endpoint, 1, allowed_ips)

        # Monitor RX bytes. The other end has also set persistent-keepalive=1, so we should see our
        # received bytes increase with 32 bytes every second
        rx_bytes = self.rx_bytes()
        time.sleep(10)
        new_rx_bytes = self.rx_bytes()
        if new_rx_bytes > rx_bytes + 32 * 5:
            log.debug('p2p connection appears to be working')
            # Keepalive can now be increased to 25 seconds
            self.update_peer(peer.pubkey, endpoint, 25)
            return
            # con = self.nm.get_connection_by_uuid(self.nm_uuid)

        # Even if the two ends of a peer to peer connection decide differently on whether the
        # connection is working, they will still end up both using the same method, because
        # WireGuard updates its endpoint when it receives data from a different source address.

        log.debug('too little RX bytes, from %s to %s', rx_bytes, new_rx_bytes)
        log.info('P2P connection to %s failed, falling back to relay server', peer.pubkey)
        # Set endpoint to relay server, also increase keepalive
        self.update_peer(peer.pubkey, self.relay_endpoint, 25)

    def rx_bytes(self) -> int:
        path = Path('/sys/class/net') / self.if_name / 'statistics' / 'rx_bytes'
        return int(path.read_text(encoding='utf-8'))

    @staticmethod
    def gen_privkey():
        return run(['wg', 'genkey'], capture_output=True)[:-1]

    @staticmethod
    def gen_pubkey(privkey: str):
        return run(['wg', 'pubkey'], stdin=privkey.encode(), capture_output=True)[:-1]

# Examples for NetworkManager WireGuard PyGObject:
# https://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/examples/python/gi/nm-wg-set
# https://github.com/eduvpn/python-eduvpn-client/blob/6412f143aaac0b96ae08f668845d40ec4b420eff/eduvpn/nm.py
class NMWGManager(WGManager):
    nm_uuid: Optional[str] = None
    nm: Optional['NM.Client'] = None
    glib_loop: Optional['GLib.MainLoop'] = None

    def _get_connection(self):
        return self.nm.get_connection_by_uuid(self.nm_uuid)

    def _get_wireguard_setting(self):
        con = self._get_connection()
        for setting in con.get_settings():
            if isinstance(setting, NM.SettingWireGuard):
                return setting
        return None

    def _get_device(self):
        for device in self.nm.get_all_devices():
            if device.get_type_description() == "wireguard" \
                and self.nm_uuid in {conn.get_uuid() for conn in device.get_available_connections()}:
                return device
        return None

    def create_interface(self, callback):
        self.glib_loop = GLib.MainLoop()
        Thread(target=self.glib_loop.run).start()

        self.nm_uuid = str(uuid.uuid4())

        GLib.idle_add(lambda: self._create_interface(callback))

    def _create_interface(self, callback):
        s_con = NM.SettingConnection.new()
        s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'wireguard')
        s_con.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, self.if_name)
        s_con.set_property(NM.SETTING_CONNECTION_ID, self.if_name)
        s_con.set_property(NM.SETTING_CONNECTION_UUID, self.nm_uuid)

        s_ip4 = NM.SettingIP4Config.new()
        s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, 'manual')
        s_ip4.add_address(NM.IPAddress(socket.AF_INET, self.addr4, 24))

        s_wg = NM.SettingWireGuard.new()
        s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY, self.privkey)
        s_wg.set_property(NM.SETTING_WIREGUARD_MTU, self.mtu)

        profile = NM.SimpleConnection.new()
        for s in (s_con, s_ip4, s_wg):
            profile.add_setting(s)

        self.nm = NM.Client.new(None)

        def add_callback(nm2, result):
            log.debug('add_callback')
            nm2.add_connection_finish(result)
            time.sleep(.5)
            GLib.idle_add(lambda: self._activate_connection(callback))

        log.debug('add_async')
        self.nm.add_connection_async(connection=profile, save_to_disk=False, callback=add_callback)

    def _activate_connection(self, callback):
        def activate_callback(a, res):
            log.debug('activate_callback')
            a.activate_connection_finish(res)
            callback()

        log.debug('activate_async')
        self.nm.activate_connection_async(connection=self._get_connection(), callback=activate_callback)

    def remove_interface(self, callback):
        def delete_callback(a, res):
            log.debug('delete_finish')
            a.delete_finish(res)
            self.glib_loop.quit()
            callback()

        def disconnect_callback(a, res):
            log.debug('disconnect_finish')
            a.disconnect_finish(res)
            con = self._get_connection()
            con.delete_async(callback=delete_callback)

        def disconnect():
            log.debug('disconnect_async')
            device = self._get_device()
            device.disconnect_async(callback=disconnect_callback)

        GLib.idle_add(disconnect)

    def list_peers(self):
        return []  # TODO

    def add_peer(self, pubkey: str, endpoint: str, keepalive: int, allowed_ips: list[str]) -> None:
        peer = NM.WireGuardPeer.new()
        peer.set_endpoint(endpoint, allow_invalid=False)
        peer.set_public_key(pubkey, accept_invalid=False)
        peer.set_persistent_keepalive(keepalive)
        for ip in allowed_ips:
            peer.append_allowed_ip(ip.strip(), accept_invalid=False)
        # TODO reload configuration

    def remove_peer(self, pubkey: str) -> None:
        s_wg = self._get_wireguard_setting()
        pp_peer, pp_idx = s_wg.get_peer_by_public_key(pubkey)
        if pp_peer:
            s_wg.remove_peer(pp_idx)
        # TODO reload configuration

    def update_peer(self, pubkey: str, endpoint: str, keepalive: int) -> None:
        s_wg = self._get_wireguard_setting()
        pp_peer, _pp_idx = s_wg.get_peer_by_public_key(pubkey)
        pp_peer.set_endpoint(endpoint)
        pp_peer.set_persistent_keepalive(keepalive)
        # TODO reload configuration


class WGToolsWGManager(WGManager):
    def create_interface(self, callback):
        privkey_path = create_tempfile(self.privkey.encode())
        run(['ip', 'link', 'add', self.if_name, 'type', 'wireguard'])
        run(['wg', 'set', self.if_name, 'private-key', privkey_path, 'listen-port', str(self.listen_port)])
        run(['ip', 'address', 'add', self.addr4 + '/24', 'dev', self.if_name])
        run(['ip', 'address', 'add', self.addr6 + '/64', 'dev', self.if_name])
        run(['ip', 'link', 'set', 'mtu', str(self.mtu), 'up', 'dev', self.if_name])
        os.unlink(privkey_path)
        callback()

    def remove_interface(self, callback):
        run(['ip', 'link', 'del', self.if_name])
        callback()

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

    def update_peer(self, pubkey: str, endpoint: str, keepalive: int) -> None:
        run(['wg', 'set', self.if_name, 'peer', pubkey, 'endpoint', endpoint, 'persistent-keepalive', str(keepalive)])


def get_wireguard(use_nm, *args) -> WGManager:
    if use_nm:
        import gi
        gi.require_version("NM", "1.0")
        from gi.repository import NM as NM2, GLib as GLib2
        global NM, GLib
        NM = NM2
        GLib = GLib2
        return NMWGManager(*args)
    else:
        global loop
        loop = None
        return WGToolsWGManager(*args)
