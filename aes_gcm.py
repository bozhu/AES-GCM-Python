#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long


def reverse_128bit(n):
    res = 0
    for i in range(128):
        res <<= 1
        res += n & 1
        n >>= 1
    return res


# GF(128) defined by 1 + a + a^2 + a^7 + a^128
def gf128_mul(x, y):
    assert x < 1 << 128
    assert y < 1 << 128

    x = reverse_128bit(x)
    y = reverse_128bit(y)
    res = 0
    for i in range(128):
        res ^= x * (y & 1)  # branchless
        y >>= 1

        rmd = (x >> 127) * 0b10000111
        x = (x % (1 << 127)) << 1
        x ^= rmd

    assert res < 1 << 128
    return reverse_128bit(res)


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
    def __init__(self, master_key):
        # check type of master_key
        self.change_key(master_key)

    def change_key(self, master_key):
        assert master_key < (1 << 128)
        self.__master_key = long_to_bytes(master_key, 16)
        self.__aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)
        self.__auth_key = bytes_to_long(self.__aes_ecb.encrypt(b'\x00' * 16))
        print 'H\t', hex(self.__auth_key)

        # precompute the table for multiplication in finite field
        table = []
        for i in range(16):
            row = []
            for j in range(256):
                row.append(gf128_mul(self.__auth_key, j << (8 * i)))
            table.append(tuple(row))
        self.__pre_table = tuple(table)

    def __times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8
        return res

    def encrypt(self, init_value, plaintext, auth_data=b''):
        assert init_value < (1 << 96)
        len_auth_data = len(auth_data)
        len_plaintext = len(plaintext)

        if len_plaintext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(init_value, 12),
                initial_value=2,  # notice this
                allow_wraparound=True)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)
            # pad plaintext
            assert len(plaintext) % 16 == 0
            ciphertext = aes_ctr.encrypt(plaintext)
        else:
            ciphertext = b''

        # pad auth_data
        auth_tag = 0
        if len_auth_data > 0:
            pass
        if len_plaintext > 0:
            for i in range(len_plaintext // 16):
                auth_tag ^= bytes_to_long(ciphertext[i * 16: (i + 1) * 16])
                # auth_tag = self.__times_auth_key(auth_tag)
                print 'pre X\t', hex(auth_tag)
                auth_tag = gf128_mul(auth_tag, self.__auth_key)
                print 'X\t', hex(auth_tag)
        if len_auth_data + len_plaintext > 0:
            print 'len\t', \
                    hex(((8 * len_auth_data) << 64) | (8 * len_plaintext))
            auth_tag ^= ((8 * len_auth_data) << 64) | (8 * len_plaintext)
            # auth_tag = self.__times_auth_key(auth_tag)
            auth_tag = gf128_mul(auth_tag, self.__auth_key)
        print 'GHASH\t', hex(auth_tag)
        auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(
                                  long_to_bytes((init_value << 32) | 1, 16)))

        # unpad ciphertext
        assert len(ciphertext) == len_plaintext
        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_data=b''):
        assert init_value < (1 << 96)
        # TODO


if __name__ == '__main__':
    # print bin(gf128_mul(1, 2))
    print bin(gf128_mul(2, 1))
    print bin(gf128_mul(2 ** 2, 2 ** 127))
    print hex(gf128_mul(0x5e2ec746917062882c85b0685353deb7 ^ 0x80, 0x66e94bd4ef8a2c3b884cfa59ca342b2e))

    master_key = 0x00000000000000000000000000000000
    plaintext = b'\x00\x00\x00\x00\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00\x00\x00\x00\x00'
    auth_data = b''
    init_value = 0x000000000000000000000000
    ciphertext = b'\x03\x88\xda\xce\x60\xb6\xa3\x92' + \
                 b'\xf3\x28\xc2\xb9\x71\xb2\xfe\x78'
    auth_tag = 0xab6e47d42cec13bdf53a67b21257bddf

    my_gcm = AES_GCM(master_key)
    cipher, tag = my_gcm.encrypt(init_value, plaintext, auth_data)
    print 'C\t', hex(bytes_to_long(cipher))
    print 'T\t', hex(tag)
