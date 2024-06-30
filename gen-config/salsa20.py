import struct

def _rotl(value, shift):
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))

def _s20_quarterround(y0, y1, y2, y3):
    y1 ^= _rotl((y0 + y3) & 0xffffffff, 7)
    y2 ^= _rotl((y1 + y0) & 0xffffffff, 9)
    y3 ^= _rotl((y2 + y1) & 0xffffffff, 13)
    y0 ^= _rotl((y3 + y2) & 0xffffffff, 18)
    return y0, y1, y2, y3

def _s20_rowround(y):
    y[0], y[1], y[2], y[3] = _s20_quarterround(y[0], y[1], y[2], y[3])
    y[5], y[6], y[7], y[4] = _s20_quarterround(y[5], y[6], y[7], y[4])
    y[10], y[11], y[8], y[9] = _s20_quarterround(y[10], y[11], y[8], y[9])
    y[15], y[12], y[13], y[14] = _s20_quarterround(y[15], y[12], y[13], y[14])

def _s20_columnround(x):
    x[0], x[4], x[8], x[12] = _s20_quarterround(x[0], x[4], x[8], x[12])
    x[5], x[9], x[13], x[1] = _s20_quarterround(x[5], x[9], x[13], x[1])
    x[10], x[14], x[2], x[6] = _s20_quarterround(x[10], x[14], x[2], x[6])
    x[15], x[3], x[7], x[11] = _s20_quarterround(x[15], x[3], x[7], x[11])

def _s20_doubleround(x):
    _s20_columnround(x)
    _s20_rowround(x)

def _s20_littleendian(b):
    return struct.unpack_from('<I', b)[0]

def _s20_rev_littleendian(b, w):
    struct.pack_into('<I', b, 0, w)

def _s20_hash(seq):
    x = [(seq[i*4] | (seq[i*4+1] << 8) | (seq[i*4+2] << 16) | (seq[i*4+3] << 24)) for i in range(16)]
    z = x[:]
    for _ in range(10):
        _s20_doubleround(z)
    for i in range(16):
        z[i] = (z[i] + x[i]) & 0xffffffff
        tmp = bytearray(4)
        _s20_rev_littleendian(tmp, z[i])
        seq[4*i:4*(i+1)] = tmp

def _s20_expand16(k, n, keystream):
    t = [
        [ord('e'), ord('x'), ord('p'), ord('g')],
        [ord('n'), ord('d'), ord(' '), ord('1')],
        [ord('6'), ord('-'), ord('b'), ord('y')],
        [ord('q'), ord('e'), ord(' '), ord('k')]
    ]

    for i in range(0, 64, 20):
        for j in range(4):
            keystream[i + j] = t[i // 20][j]

    keystream[4:20] = k[:16]
    keystream[44:60] = k[:16]
    keystream[24:40] = n
    _s20_hash(keystream)


def s20_crypt(key, nonce, buf):
    si = 0
    keystream = bytearray(64)
    n = bytearray(16)
    n[:8] = nonce

    buf = bytearray(buf)  # Ensure buf is mutable

    if si % 64 != 0:
        _s20_rev_littleendian(n[8:12], si // 64)
        _s20_expand16(key, n, keystream)

    for i in range(len(buf)):
        if (si + i) % 64 == 0:
            tmp = bytearray([0, 0, 0, 0])
            _s20_rev_littleendian(tmp, (si + i) // 64)
            n[8:12] = tmp
            _s20_expand16(key, n, keystream)
        buf[i] ^= keystream[(si + i) % 64]
    return buf

