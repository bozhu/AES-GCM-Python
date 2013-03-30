#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long


# GF(128) defined by 1 + a + a^2 + a^7 + a^128
# Please note the MSB is x0 and LSB is x127
def gf128_mul(x, y):
    assert x < 1 << 128
    assert y < 1 << 128
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
    def __init__(self, master_key):
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

    def __times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8
        return res

    def __ghash(self, aad, txt):
        len_aad = len(aad)
        len_txt = len(txt)
        assert len_aad % 16 == 0
        assert len_txt % 16 == 0
        data = aad + txt

        tag = 0
        for i in range((len_aad + len_txt) // 16):
            tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
            tag = self.__times_auth_key(tag)
            # print 'X\t', hex(tag)
        tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
        tag = self.__times_auth_key(tag)

        return tag

    def encrypt(self, init_value, plaintext, auth_data=b''):
        assert init_value < (1 << 96)
        # len_auth_data = len(auth_data)
        len_plaintext = len(plaintext)

        if len_plaintext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(init_value, 12),
                initial_value=2,  # notice this
                allow_wraparound=True)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)
            # TODO: pad plaintext
            assert len(plaintext) % 16 == 0
            ciphertext = aes_ctr.encrypt(plaintext)
        else:
            ciphertext = b''

        # TODO: pad auth_data
        auth_tag = self.__ghash(auth_data, ciphertext)
        # print 'GHASH\t', hex(auth_tag)
        auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(
                                  long_to_bytes((init_value << 32) | 1, 16)))

        # TODO: unpad ciphertext
        assert len(ciphertext) == len_plaintext
        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_data=b''):
        assert init_value < (1 << 96)
        # TODO


if __name__ == '__main__':
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
