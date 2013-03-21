#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long


# encryption in counter mode
def cm_enc(cipher_enc, init_val, plain):
    assert init_val < (1 << 96)
    counter_base = init_val << 32
    counter = 1

    len_plain = len(plain)
    cipher_val = [0] * (len_plain // 16 + 1)
    for i in range(len_plain // 16):
        cipher_val[i] = bytes_to_long(cipher_enc(counter_base | counter)) ^ \
                long_to_bytes(plain[i * 16: (i + 1) * 16], 16)
        counter = (counter + 1) % (1 << 32)
    # Please note in original design of GCM, padding is in bits
    # But here we only handle the situation that input is in bytes
    padding_bytes = len_plain - 16 * (len_plain // 16)
    cipher_val[-1] = \
            bytes_to_long(cipher_enc(counter_base | counter)) \
            >> (8 * padding_bytes) ^ \
            long_to_bytes(plain[16 * (len_plain // 16):])
    return cipher_val


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
    def __init__(self, master_key):
        self.change_key(master_key)

    def change_key(self, master_key):
        key_bytestr = long_to_bytes(master_key, 16)
        assert len(key_bytestr) == 16
        self.__aes = AES.new(key_bytestr, AES.MODE_ECB)

    def encrypt(self, init_value, auth_data, plaintext):
        cipher_value = cm_enc(self.__aes.encrypt, init_value, plaintext)

    def decrypt(self, init_value, auth_data, ciphertext):
        assert init_value < (1 << 96)


if __name__ == '__main__':
    pass
