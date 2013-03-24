#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes  # , bytes_to_long


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
    def __init__(self, master_key):
        self.change_key(master_key)

    def change_key(self, master_key):
        assert master_key < (1 << 128)
        self.__master_key = long_to_bytes(master_key, 16)
        aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)
        self.__auth_key = aes_ecb.encrypt(b'\x00' * 16)

    def encrypt(self, init_value, auth_data, plaintext):
        assert init_value < (1 << 96)
        counter = None
        aes_ctr = None
        ciphertext = None
        auth_tag = None
        return ciphertext, auth_tag

    def decrypt(self, init_value, auth_data, ciphertext):
        assert init_value < (1 << 96)


if __name__ == '__main__':
    pass
