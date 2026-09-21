import ctypes as c
import errno
import socket
import struct

lib = c.CDLL(None, use_errno=True)
SO_PEERNAME = 28


def peer_name(sock):
    address = sock.getsockopt(socket.SOL_SOCKET, SO_PEERNAME, 16)
    return socket.inet_ntoa(address[4:8]), struct.unpack("!H", address[2:4])[0]


def check_peer_option(sock, target):
    expected = (
        struct.pack("=H", socket.AF_INET)
        + struct.pack("!H", target[1])
        + socket.inet_aton(target[0])
        + bytes(8)
    )
    assert sock.getpeername() == peer_name(sock) == target
    for capacity in (0, 1, 4, 8, 15, 16, 17, 128, -1):
        buffer = c.create_string_buffer(b"X" * 128, 128)
        length = c.c_int(capacity)
        result = lib.getsockopt(
            sock.fileno(), socket.SOL_SOCKET, SO_PEERNAME, buffer, c.byref(length)
        )
        assert length.value == capacity, (capacity, length.value)
        if 0 <= capacity <= 16:
            assert result == 0, (capacity, c.get_errno())
            assert buffer.raw[:capacity] == expected[:capacity]
            assert buffer.raw[capacity:] == b"X" * (128 - capacity)
        else:
            assert result == -1 and c.get_errno() == errno.EINVAL
            assert buffer.raw == b"X" * 128
    length = c.c_int(16)
    assert (
        lib.getsockopt(
            sock.fileno(), socket.SOL_SOCKET, SO_PEERNAME, None, c.byref(length)
        )
        == -1
    )
    assert c.get_errno() == errno.EFAULT
    buffer = c.create_string_buffer(16)
    assert (
        lib.getsockopt(sock.fileno(), socket.SOL_SOCKET, SO_PEERNAME, buffer, None) == -1
    )
    assert c.get_errno() == errno.EFAULT


class Iovec(c.Structure):
    _fields_ = [("base", c.c_void_p), ("length", c.c_size_t)]


class Msghdr(c.Structure):
    _fields_ = [
        ("name", c.c_void_p),
        ("name_length", c.c_uint),
        ("iov", c.POINTER(Iovec)),
        ("iov_length", c.c_size_t),
        ("control", c.c_void_p),
        ("control_length", c.c_size_t),
        ("flags", c.c_int),
    ]


class Mmsghdr(c.Structure):
    _fields_ = [("header", Msghdr), ("length", c.c_uint)]


def batch_oob(sock, receive):
    buffer = c.create_string_buffer(b"!")
    vector = Iovec(c.cast(buffer, c.c_void_p), 1)
    message = Mmsghdr(Msghdr(iov=c.pointer(vector), iov_length=1), 0)
    args = (sock.fileno(), c.byref(message), 1, socket.MSG_OOB | socket.MSG_DONTWAIT)
    result = lib.recvmmsg(*args, None) if receive else lib.sendmmsg(*args)
    if result < 0:
        error = c.get_errno()
        raise OSError(error, "batched OOB operation")
    return result


def check_oob_rejected(sock):
    flags = socket.MSG_OOB | socket.MSG_DONTWAIT
    timeout = sock.gettimeout()
    # Skip Python's readiness wait so each receive reaches the syscall.
    sock.setblocking(False)
    try:
        for operation in (
            lambda: sock.send(b"!", flags),
            lambda: sock.sendmsg([b"!"], [], flags),
            lambda: batch_oob(sock, False),
            lambda: sock.recv(1, flags),
            lambda: sock.recvmsg(1, 0, flags),
            lambda: batch_oob(sock, True),
        ):
            try:
                operation()
                raise AssertionError("relayed OOB operation succeeded")
            except OSError as error:
                assert error.errno == errno.EOPNOTSUPP, error
    finally:
        sock.settimeout(timeout)
