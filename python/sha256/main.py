K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def rotr(x, n, width=32):
    n %= width
    if n < 1:
        return x
    mask = (2**width - 1)
    x &= mask
    return (x >> n) | ((x << (width - n)) & mask)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sig0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sig1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def ctn(x, y, width):
    return (x << width + y)

def sha256(byte_array):
    # Padding
    l = 8 * len(byte_array)
    k = (448 - l - 1) % 512
    padding = ((1 << k) << 64) + l
    byte_array_padding = []
    for i in range((1 + k + 64)//8):
        byte_array_padding.insert(0, padding - (padding >> 8 << 8))
        padding = padding >> 8

    byte_array_padded = byte_array + byte_array_padding

    # Block Decomposition
    M_W = []
    mask = (2**32 - 1)
    for M_start in range(len(byte_array_padded)//64):
        M = byte_array_padded[M_start:64]
        W = []
        # 16 first
        for i in range(16):
            W.append((M[4*i] << 24) + (M[4*i+1] << 16) + (M[4*i+2] << 8) + M[4*i+3])
        # 48 next
        for i in range(16, 64):
            W.append((sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16]) & mask)
        M_W.append(W)

    # Hash Computation
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for W in M_W:
        a, b, c, d, e, f, g, h = H
        for j in range(64):
            T1 = h + sigma1(e) + ch(e, f, g) + K[j] + W[j]
            T2 = sigma0(a) + maj(a, b, c)
            h = g
            g = f
            f = e
            e = (d + T1) & mask
            d = c
            c = b
            b = a
            a = (T1 + T2) & mask
        H = [(x + y) & mask for x, y in zip(H, [a, b, c, d, e, f, g, h])]
    H = ' '.join(list(map(hex, H)))
    return H

if __name__ == '__main__':
    msg = [97, 98, 99]
    hash_msg = sha256(msg)
    print(hash_msg)
    assert (hash_msg == "0xba7816bf 0x8f01cfea 0x414140de 0x5dae2223 0xb00361a3 0x96177a9c 0xb410ff61 0xf20015ad"), "Wrong hash message"
