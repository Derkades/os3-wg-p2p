import socket


SINGLE_PEER: dict[str, tuple[str, int]] = {}
PEER_PAIRS: dict[tuple[str, int], tuple[str, int]] = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 3000))

while True:
    data, addr = sock.recvfrom(1420)
    if data.startswith(b'magic'):
        uuid = data[5:].decode()
        if addr in PEER_PAIRS:
            print('already registered as pair')
            continue

        if uuid in SINGLE_PEER:
            other_peer = SINGLE_PEER[uuid]
            print('uuid already exists, pair with peer', other_peer)
            PEER_PAIRS[addr] = other_peer
            PEER_PAIRS[other_peer] = addr
        else:
            print('register uuid (first)    :', uuid)
            SINGLE_PEER[uuid] = addr
    else:
        print(f"received message: {data} from {addr}")
        if addr not in PEER_PAIRS:
            print('ignoring message without peer pair')
            continue

        other_peer = PEER_PAIRS[addr]
        print(f'forwarding message from {addr} to {other_peer}')
        sock.sendto(data, other_peer)
