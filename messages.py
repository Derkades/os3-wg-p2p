import gzip
import json
import struct
from abc import ABC
from dataclasses import asdict, dataclass
from gzip import BadGzipFile
from ipaddress import IPv4Address
from json import JSONDecodeError
from typing import Optional

MAGIC = b'awesome peer to peer magic to distinguish packet as different from wiregurad traffic'


@dataclass
class AddressResponse:
    SIZE = 6
    FORMAT = '!4sH'
    host: str # IPv4 address (4 bytes)
    port: int # port number (2 bytes)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, IPv4Address(self.host).packed, self.port)

    @classmethod
    def unpack(cls, packed: bytes):
        host, port = struct.unpack(cls.FORMAT, packed)
        return cls(str(IPv4Address(host)), port)


class Message(ABC):
    pass


@dataclass
class PeerHello(Message):
    uuid: str # uuid
    pubkey: str # wireguard pubkey
    vpn_addr4: str # IPv4 address inside the VPN
    vpn_addr6: str # IPV6 address inside the VPN
    host: str # for wireguard udp
    port: str # for wireguard udp


@dataclass
class PeerInfo:
    host: str
    port: int
    pubkey: str
    vpn_addr4: str
    vpn_addr6: str


@dataclass
class PeerList(Message):
    peers: list[PeerInfo]


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
        return PeerHello(**obj)
    elif type == 'PeerList':
        return PeerList([PeerInfo(**peer) for peer in obj['peers']])
    raise ValueError(type)
