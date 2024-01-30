import logging
import os
import socket
import subprocess
import tempfile
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import Optional

import udp
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
    ipv6: bool
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

    @abstractmethod
    def peer_rx(self, pubkey: str) -> int:
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

    def _find_source_ip(self, dest_ip: str) -> str:
        # There must be a better way...
        output = run(['ip', 'route', 'get', dest_ip], capture_output=True)
        dev = False
        for part in output.split():
            if dev:
                iface = part.strip()
                break
            dev = part.strip() == 'dev'

        output = run(['ip', 'addr', 'show', iface], capture_output=True)
        inet = False
        for part in output.split():
            if inet:
                return part.strip().split('/')[0]
            inet = part.strip() == 'inet'

    def set_up_peer_connection(self, peer: PeerInfo):
        peer_addr = None
        if self.ipv6 and peer.addr6:
            # can only connect to IPv6-only host directly
            peer_addr = peer.addr6
        elif not self.ipv6 and peer.addr4:
            # can connect to IPv4-only or dual stack host
            peer_addr = peer.addr4

        allowed_ips = [f'{peer.vpn_addr4}/32', f'{peer.vpn_addr6}/128']

        if not peer_addr:
            log.info('peer %s uses different address family, must use relay', peer.pubkey)
            self.add_peer(peer.pubkey, self.relay_endpoint, 25, allowed_ips)
            return

        log.info('trying p2p connection to peer: %s %s', peer.pubkey, peer_addr)

        # UDP hole punching
        try:
            source_ip = self._find_source_ip(peer_addr[0])
            source = (source_ip, self.listen_port)
            udp.send(b'', source, peer_addr)
        except PermissionError:
            log.warning('no permission to send raw udp for hole punching, are you root?')
        # Add peer with low keepalive
        endpoint = f'{peer_addr[0]}:{peer_addr[1]}'

        self.add_peer(peer.pubkey, endpoint, 1, allowed_ips)

        # Monitor RX bytes. The other end has also set persistent-keepalive=1, so we should see our
        # received bytes increase with 32 bytes every second
        rx_bytes = self.peer_rx(peer.pubkey)
        time.sleep(7)
        new_rx_bytes = self.peer_rx(peer.pubkey)
        log.debug('rx from %s to %s', rx_bytes, new_rx_bytes)
        if new_rx_bytes > rx_bytes:
            log.info('p2p connection appears to be working')
            # Keepalive can now be increased to 25 seconds
            self.update_peer(peer.pubkey, endpoint, 25)
            return

        # Even if the two ends of a peer to peer connection decide differently on whether the
        # connection is working, they will still end up both using the same method, because
        # WireGuard updates its endpoint when it receives data from a different source address.

        log.info('p2p connection to %s failed, falling back to relay server', peer.pubkey)
        # Set endpoint to relay server, also increase keepalive
        self.update_peer(peer.pubkey, self.relay_endpoint, 25)

    @staticmethod
    def gen_privkey():
        return run(['wg', 'genkey'], capture_output=True)[:-1]

    @staticmethod
    def gen_pubkey(privkey: str):
        return run(['wg', 'pubkey'], stdin=privkey.encode(), capture_output=True)[:-1]

# Documentation: https://github.com/Derkades/os3-wg-p2p/issues/4#issuecomment-1909762430
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
        return self.nm.get_device_by_iface(self.if_name)

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
        s_wg.set_property(NM.SETTING_WIREGUARD_LISTEN_PORT, self.listen_port)
        s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY, self.privkey)
        s_wg.set_property(NM.SETTING_WIREGUARD_MTU, self.mtu)

        profile = NM.SimpleConnection.new()
        for s in (s_con, s_ip4, s_wg):
            profile.add_setting(s)

        self.nm = NM.Client.new(None)

        def add_callback(nm2, result):
            log.debug('add_callback')
            nm2.add_connection_finish(result)
            callback()

        log.debug('add_async')
        self.nm.add_connection_async(connection=profile, save_to_disk=False, callback=add_callback)

    def remove_interface(self, callback):
        def delete_callback(a, res):
            log.debug('delete_finish')
            a.delete_finish(res)
            self.glib_loop.quit()
            callback()

        def delete():
            log.debug('delete connection')
            con = self._get_connection()
            con.delete_async(callback=delete_callback)

        def disconnect_callback(a, res):
            log.debug('disconnect_finish')
            a.disconnect_finish(res)
            delete()

        def disconnect():
            device = self._get_device()
            if device:
                log.debug('disconnect_async')
                device.disconnect_async(callback=disconnect_callback)
            else:
                log.warning('device does not exist, already disconnected?')
                delete()

        GLib.idle_add(disconnect)

    def list_peers(self):
        s_wg = self._get_wireguard_setting()
        return [s_wg.get_peer(i).get_public_key() for i in range(s_wg.get_peers_len())]

    def update(self):
        def reapply_callback(a, res):
            log.debug('reapply_callback')
            a.reapply_finish(res)
            log.debug('peers after apply: %s', self.list_peers())

        def reapply():
            log.debug('reapply_async')
            log.debug('peers before apply: %s', self.list_peers())
            con = self._get_connection()
            self._get_device().reapply_async(con, 0, 0, callback=reapply_callback)

        def commit_callback(a, res):
            log.debug('commit_callback')
            a.commit_changes_finish(res)
            reapply()

        def commit():
            log.debug('peers before commit_changes: %s', self.list_peers())
            log.debug('commit_changes_async')
            con = self._get_connection()
            con.commit_changes_async(save_to_disk=False, callback=commit_callback)

        GLib.idle_add(commit)

    def add_peer(self, pubkey: str, endpoint: str, keepalive: int, allowed_ips: list[str]) -> None:
        peer = NM.WireGuardPeer.new()
        peer.set_endpoint(endpoint, allow_invalid=False)
        peer.set_public_key(pubkey, accept_invalid=False)
        peer.set_persistent_keepalive(keepalive)
        for ip in allowed_ips:
            peer.append_allowed_ip(ip.strip(), accept_invalid=False)

        s_wg = self._get_wireguard_setting()
        s_wg.append_peer(peer)
        self.update()

    def remove_peer(self, pubkey: str) -> None:
        s_wg = self._get_wireguard_setting()
        pp_peer, pp_idx = s_wg.get_peer_by_public_key(pubkey)
        if pp_peer:
            s_wg.remove_peer(pp_idx)
            self.update()
        else:
            log.warning('peer %s does not exist', pubkey)
            log.debug('peers: %s', self.list_peers())

    def update_peer(self, pubkey: str, endpoint: str, keepalive: int) -> None:
        s_wg = self._get_wireguard_setting()
        pp_peer, pp_idx = s_wg.get_peer_by_public_key(pubkey)
        if pp_peer:
            peer = pp_peer.new_clone(True)
            peer.set_endpoint(endpoint, allow_invalid=False)
            peer.set_persistent_keepalive(keepalive)
            s_wg.set_peer(peer, pp_idx)
            self.update()
        else:
            log.warning('peer %s does not exist', pubkey)
            log.debug('peers: %s', self.list_peers())

    def peer_rx(self, pubkey: str) -> int:
        log.warning('cannot determine per-peer rx bytes using network manager')
        log.warning('returning interface rx bytes, unreliable when multiple peers are active')
        try:
            path = Path('/sys/class/net') / self.if_name / 'statistics' / 'rx_bytes'
            return int(path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            log.warning('cannot read rx_bytes')
            return 0


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

    def peer_rx(self, pubkey: str) -> int:
        output = run(['wg', 'show', self.if_name, 'transfer'], capture_output=True)
        for line in output.splitlines():
            cols = line.split()
            if cols[0].strip() == pubkey:
                return int(cols[1].strip())
        log.warning('could not determine rx bytes for %s', pubkey)
        return 0


def get_wireguard(use_nm, *args) -> WGManager:
    if use_nm:
        import gi
        gi.require_version("NM", "1.0")
        from gi.repository import NM as NM2
        from gi.repository import GLib as GLib2
        global NM, GLib
        NM = NM2
        GLib = GLib2
        return NMWGManager(*args)
    else:
        return WGToolsWGManager(*args)
