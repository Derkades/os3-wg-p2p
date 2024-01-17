1. Peer sends UDP message to server. This source port is later used for the WG interface.
2. Server replies with "address response" containing the client's source address and port as seen by the server.
3. Peer sends second "peer hello" TCP message to server. The second source port becomes the management port.
  - WG addr and port as received in "address" response. In relay mode, the server needs this to send packets to. In p2p mode, the server needs to send this to the other peer.
  - pubkey
  - vpn addr v4 and v6
4. Server responds many "peer info" with a list of all peers.
5. Network is registered containing single peer.
6. Peer list is sent to all nodes.
