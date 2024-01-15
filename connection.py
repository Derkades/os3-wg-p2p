import struct
from base64 import b64encode, b64decode
from dataclasses import dataclass

MAGIC_HEADER = b'awesome peer to peer'


@dataclass
class ConnectionRequest:
    _format = '!?32s128s128s'
    relay: bool
    pubkey: str # wireguard pubkey (32 bytes)
    uuid: str # unique id in text format (128 bytes) TODO: more efficient
    vpn_addr: str # address inside the VPN (128 bytes) TODO: more efficient

    def pack(self) -> bytes:
        return struct.pack(self._format, self.relay, b64decode(self.pubkey), self.uuid.encode(), self.vpn_addr.encode())

    @classmethod
    def unpack(cls, inp: bytes) -> 'ConnectionRequest':
        relay, pubkey, uuid, vpn_addr = struct.unpack(cls._format, inp)
        return cls(relay, b64encode(pubkey).decode(), uuid.decode(), vpn_addr.rstrip(b'\x00').decode())


@dataclass
class ConnectionResponse:
    _format = '!32s128sH128s'
    peer_pubkey: str # wireguard pubkey of other peer (32 bytes)
    peer_host: str # IPv4 or IPv6 address of other peer (128 bytes) TODO: more efficient
    peer_port: int # port number of other peer (2 bytes)
    peer_vpn_addr: bytes # address inside the VPN (128 bytes) # TODO: more efficient

    def pack(self) -> bytes:
        return struct.pack(self._format, b64decode(self.peer_pubkey), self.peer_host.encode(), self.peer_port, self.peer_vpn_addr.encode())

    @classmethod
    def unpack(cls, inp: bytes) -> 'ConnectionResponse':
        pubkey, addr, port, vpn_addr = struct.unpack(cls._format, inp)
        return cls(b64encode(pubkey).decode(), addr.decode(), port, vpn_addr.rstrip(b'\x00').decode())
