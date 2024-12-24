import struct
import math

class SHA1:
    def __init__(self):
        self._h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]

    def _left_rotate(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def digest(self, data):
        data = bytearray(data)
        orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
        data.append(0x80)
        while (len(data) % 64) != 56:
            data.append(0)
        data += struct.pack(b">Q", orig_len_bits)

        for chunk_start in range(0, len(data), 64):
            w = list(struct.unpack(b">16I", data[chunk_start:chunk_start + 64])) + [0] * 64
            for i in range(16, 80):
                w[i] = self._left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

            a, b, c, d, e = self._h

            for i in range(80):
                if i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (self._left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
                e, d, c, b, a = d, c, self._left_rotate(b, 30), a, temp

            self._h = [
                (x + y) & 0xFFFFFFFF for x, y in zip(self._h, [a, b, c, d, e])
            ]

        return "".join(f"{value:08x}" for value in self._h)

class SHA256:
    def __init__(self):
        self._h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self._k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def _right_rotate(self, n, b):
        return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

    def digest(self, data):
        data = bytearray(data)
        orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
        data.append(0x80)
        while (len(data) % 64) != 56:
            data.append(0)
        data += struct.pack(b">Q", orig_len_bits)

        for chunk_start in range(0, len(data), 64):
            w = list(struct.unpack(b">16I", data[chunk_start:chunk_start + 64])) + [0] * 48
            for i in range(16, 64):
                s0 = self._right_rotate(w[i - 15], 7) ^ self._right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = self._right_rotate(w[i - 2], 17) ^ self._right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = self._h

            for i in range(64):
                s1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + s1 + ch + self._k[i] + w[i]) & 0xFFFFFFFF
                s0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFF

                h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

            self._h = [
                (x + y) & 0xFFFFFFFF for x, y in zip(self._h, [a, b, c, d, e, f, g, h])
            ]

        return "".join(f"{value:08x}" for value in self._h)

class SHA512:
    def __init__(self):
        self._h = [
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        ]
        self._k = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ]

    def _right_rotate(self, n, b):
        return ((n >> b) | (n << (64 - b))) & 0xFFFFFFFFFFFFFFFF

    def digest(self, data):
        data = bytearray(data)
        orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        data.append(0x80)
        while (len(data) % 128) != 112:
            data.append(0)
        data += struct.pack(b">QQ", orig_len_bits >> 64, orig_len_bits & 0xFFFFFFFFFFFFFFFF)

        for chunk_start in range(0, len(data), 128):
            w = list(struct.unpack(b">16Q", data[chunk_start:chunk_start + 128])) + [0] * 64
            for i in range(16, 80):
                s0 = self._right_rotate(w[i - 15], 1) ^ self._right_rotate(w[i - 15], 8) ^ (w[i - 15] >> 7)
                s1 = self._right_rotate(w[i - 2], 19) ^ self._right_rotate(w[i - 2], 61) ^ (w[i - 2] >> 6)
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF

            a, b, c, d, e, f, g, h = self._h

            for i in range(80):
                s1 = self._right_rotate(e, 14) ^ self._right_rotate(e, 18) ^ self._right_rotate(e, 41)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + s1 + ch + self._k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
                s0 = self._right_rotate(a, 28) ^ self._right_rotate(a, 34) ^ self._right_rotate(a, 39)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFFFFFFFFFF

                h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFFFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

            self._h = [
                (x + y) & 0xFFFFFFFFFFFFFFFF for x, y in zip(self._h, [a, b, c, d, e, f, g, h])
            ]

        return "".join(f"{value:016x}" for value in self._h)


if __name__ == "__main__":
    data = b"hello world"

    sha1 = SHA1()
    print("SHA-1:", sha1.digest(data))

    sha256 = SHA256()
    print("SHA-256:", sha256.digest(data))

    sha512 = SHA512()
    print("SHA-512:", sha512.digest(data))
