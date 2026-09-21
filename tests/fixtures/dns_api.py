import socket
import struct


def dns_query(name, kind=1):
    labels = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.'))
    return b'\x12\x34\x01\x00\x00\x01' + b'\0' * 6 + labels + b'\0' + struct.pack('!HH', kind, 1)


def dns_exact(stream, count):
    data = b''
    while len(data) < count:
        part = stream.recv(count - len(data))
        assert part, 'incomplete DNS frame'
        data += part
    return data


def dns_lookup(name, tcp=False, kind=1):
    query = dns_query(name, kind)
    server = ('203.0.113.53', 53)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        if tcp:
            client.connect(server)
            client.sendall(struct.pack('!H', len(query)) + query)
            answer = dns_exact(client, struct.unpack('!H', dns_exact(client, 2))[0])
        else:
            client.sendto(query, server)
            answer, source = client.recvfrom(4096)
            assert source == server, source
    assert answer[:2] == query[:2] and answer[2] & 0x80
    assert answer[12:len(query)] == query[12:]
    assert answer[3] & 15 == 0, answer
    count = struct.unpack('!H', answer[6:8])[0]
    records = []
    offset = len(query)
    for _ in range(count):
        name, kind, cls, ttl, size = struct.unpack('!HHHIH', answer[offset:offset+12])
        assert (name, kind, cls, size) == (0xc00c, 1, 1, 4)
        records.append((socket.inet_ntoa(answer[offset+12:offset+16]), ttl))
        offset += 16
    assert offset == len(answer)
    return records
