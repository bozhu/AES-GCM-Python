#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long


# GF(128) defined by 1 + a + a^2 + a^7 + a^128
def gf128_mul(x, y):
    assert x < 1 << 128
    assert y < 1 << 128
    res = 0
    for i in range(128):
        res ^= x * (y & 1)
        y >>= 1

        rmd = (x >> 127) * 0b10000111
        x = (x % (1 << 127)) << 1
        x ^= rmd
    assert res < 1 << 128
    return res


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

        # precompute the table for multiplication in finite field
        table = []
        for i in range(16):
            row = []
            for j in range(256):
                row.append(gf128_mul(self.__auth_key, j << (8 * i)))
            table.append(tuple(row))
        self.__pre_table = tuple(table)

    def times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8

    def encrypt(self, init_value, plaintext, auth_data=b''):
        assert init_value < (1 << 96)
        len_auth_data = len(auth_data)
        len_plaintext = len(plaintext)

        if len_plaintext > 0:
            counter = Counter.new(128,
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
                auth_tag = self.__times_auth_key(auth_tag)
        auth_tag ^= self.__aes_ecb.encrypt(
                long_to_bytes(init_value << 32 | 1, 16))

        # unpad ciphertext
        assert len(ciphertext) == len_plaintext
        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_data=b''):
        assert init_value < (1 << 96)
        # TODO


if __name__ == '__main__':
    print hex(gf128_mul(32, 1213))
