import struct
from base64 import b64decode, b64encode
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from uuid import UUID

MAGIC_HEADER = b'awesome peer to peer'


@dataclass
class ConnectionRequest:  # 68 bytes
    _format = '!?32s16s4s16s'
    relay: bool
    pubkey: str # wireguard pubkey (32 bytes)
    uuid: str # uuid (16 bytes, big endian format)
    vpn_addr4: str # IPv4 address inside the VPN (4 bytes)
    vpn_addr6: str # IPV6 address inside the VPN (16 bytes)

    def pack(self) -> bytes:
        return struct.pack(self._format,
                           self.relay,
                           b64decode(self.pubkey),
                           UUID(self.uuid).bytes,
                           IPv4Address(self.vpn_addr4).packed,
                           IPv6Address(self.vpn_addr6).packed)

    @classmethod
    def unpack(cls, inp: bytes) -> 'ConnectionRequest':
        relay, pubkey, uuid, addr4, addr6 = struct.unpack(cls._format, inp)
        return cls(relay, b64encode(pubkey).decode(), str(UUID(bytes=uuid)), str(IPv4Address(addr4)), str(IPv6Address(addr6)))


@dataclass
class ConnectionResponse:  # 70 bytes
    _format = '!32s16sH4s16s'
    peer_pubkey: str # wireguard pubkey of other peer (32 bytes)
    peer_host: str # IPv4 or IPv6 address of other peer (16 bytes)
    peer_port: int # port number of other peer (2 bytes)
    peer_vpn_addr4: str # IPv4 address inside the VPN of other peer (4 bytes)
    peer_vpn_addr6: str # IPV6 address inside the VPN of other peer (16 bytes)

    def pack(self) -> bytes:
        return struct.pack(self._format,
                           b64decode(self.peer_pubkey),
                           ip_address(self.peer_host).packed,
                           self.peer_port,
                           ip_address(self.peer_vpn_addr4).packed,
                           ip_address(self.peer_vpn_addr6).packed)

    @classmethod
    def unpack(cls, inp: bytes) -> 'ConnectionResponse':
        pubkey, host, port, vpn_addr4, vpn_addr6 = struct.unpack(cls._format, inp)
        return cls(b64encode(pubkey).decode(), str(ip_address(host.rstrip(b'\x00'))), port, str(IPv4Address(vpn_addr4)), str(IPv6Address(vpn_addr6)))
