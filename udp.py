import socket
import struct
from ipaddress import IPv4Address
import logging

log = logging.getLogger('udp')

# TODO: IPv6
# TODO: Run as helper program so main program doesn't need root access

# UDP header (from RFC 768):
#   0      7 8     15 16    23 24    31
#  +--------+--------+--------+--------+
#  |     Source      |   Destination   |
#  |      Port       |      Port       |
#  +--------+--------+--------+--------+
#  |                 |                 |
#  |     Length      |    Checksum     |
#  +--------+--------+--------+--------+
#  |
#  |          data octets ...
#  +---------------- ...
#
# Pseudo header for checksum:
#   0      7 8     15 16    23 24    31
#  +--------+--------+--------+--------+
#  |          source address           |
#  +--------+--------+--------+--------+
#  |        destination address        |
#  +--------+--------+--------+--------+
#  |  zero  |protocol|   UDP length    |
#  +--------+--------+--------+--------+

def send(data, source_addr: tuple[str, int], dest_addr: tuple[str, int]):
    if ':' in dest_addr[0]:
        raise ValueError('IPv6 is not supported, cannot send to ' + dest_addr)

    log.debug('sending UDP from %s to %s', source_addr, dest_addr)

    data_len = len(data)
    udp_length = 8 + data_len
    checksum = 0
    pseudo_header = struct.pack('!4s4sBBH',
                                IPv4Address(source_addr[0]).packed, IPv4Address(dest_addr[0]).packed,
                                0, socket.IPPROTO_UDP, udp_length)
    udp_header = struct.pack('!HHHH', source_addr[1], dest_addr[1], udp_length, 0)
    checksum = _checksum_func(pseudo_header + udp_header + data)
    udp_header = struct.pack('!HHHH', source_addr[1], dest_addr[1], udp_length, checksum)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as sock:
        sock.sendto(udp_header + data, dest_addr)


# From https://github.com/houluy/UDP/blob/master/udp.py#L120
# No license! Need to find different code with open source license.
def _checksum_func(data):
    checksum = 0
    data_len = len(data)
    if (data_len % 2):
        data_len += 1
        data += struct.pack('!B', 0)

    for i in range(0, data_len, 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum
