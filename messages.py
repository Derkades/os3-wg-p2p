import gzip
import json
import struct
from abc import ABC
from dataclasses import asdict, dataclass
from gzip import BadGzipFile
from ipaddress import IPv6Address
from json import JSONDecodeError
from typing import Optional

MAGIC = b'awesome peer to peer magic to distinguish packet as different from wiregurad traffic'


@dataclass
class AddressResponse:
    SIZE = 18
    FORMAT = '!16sH'
    host: str # IPv6 address or IPv4-mapped IPv6 address (16 bytes)
    port: int # port number (2 bytes)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, IPv6Address(self.host).packed, self.port)

    @classmethod
    def unpack(cls, packed: bytes) -> 'AddressResponse':
        host, port = struct.unpack(cls.FORMAT, packed)
        return cls(str(IPv6Address(host)), port)


class Message(ABC):
    pass


@dataclass
class PeerHello(Message):
    uuid: str # uuid
    pubkey: str # wireguard pubkey
    vpn_addr4: str # IPv4 address inside the VPN
    vpn_addr6: str # IPv6 address inside the VPN
    addr4: Optional[tuple[str, int]] # for wireguard udp
    addr6: Optional[tuple[str, int]] # for wireguard udp


@dataclass
class PeerInfo:
    addr4: Optional[tuple[str, int]] # for wireguard udp
    addr6: Optional[tuple[str, int]] # for wireguard udp
    pubkey: str # wireguard public key
    vpn_addr4: str # IPv4 address inside the VPN
    vpn_addr6: str # IPv6 address inside the VPN


@dataclass
class PeerList(Message):
    peers: list[PeerInfo]


# quick and dirty message packing: gzipped json


def pack(msg: Message):
    return gzip.compress(json.dumps({'type': type(msg).__name__, **asdict(msg)}).encode())


def unpack(data) -> Optional[Message]:
    try:
        obj = json.loads(gzip.decompress(data).decode())
    except (BadGzipFile, JSONDecodeError):
        return None
    type = obj['type']
    del obj['type']
    if type == 'PeerHello':
        # rewrite list to tuple
        for name in ['addr4', 'addr6']:
            if obj[name] is not None:
                obj[name] = tuple(obj[name])
        return PeerHello(**obj)
    elif type == 'PeerList':
        return PeerList([PeerInfo(**peer) for peer in obj['peers']])
    raise ValueError(type)
