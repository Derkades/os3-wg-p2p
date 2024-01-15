import struct
from dataclasses import dataclass

MAGIC_HEADER = b'awesome peer to peer'


@dataclass
class ConnectionRequest:
    _format = '!?32s128s'
    relay: bool
    pubkey: bytes # raw wireguard pubkey (32 bytes)
    uuid: bytes # unique id in text format (128 bytes) TODO: more efficient

    def pack(self) -> bytes:
        return struct.pack(self._format, self.relay, self.pubkey, self.uuid)

    @classmethod
    def unpack(cls, inp: bytes) -> 'ConnectionRequest':
        return cls(*struct.unpack(cls._format, inp))


@dataclass
class ConnectionResponse:
    _format = '!32s128sH'
    pubkey: bytes # raw wireguard pubkey of other peer (32 bytes)
    addr: bytes # IPv4 or IPv6 address of other peer (128 bytes) TODO: more efficient
    port: int # port number of other peer (2 bytes)

    def pack(self) -> bytes:
        return struct.pack(self._format, self.pubkey, self.addr, self.port)

    @classmethod
    def unpack(cls, inp: bytes) -> 'ConnectionResponse':
        return cls(*struct.unpack(cls._format, inp))
