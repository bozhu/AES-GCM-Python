#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long


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
        # TODO precompute the table for multiplication in finite field
        self.__times_H = _gen_table(self.__auth_key)

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
            # TODO
            pass

        # unpad ciphertext
        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_data=b''):
        # TODO
        assert init_value < (1 << 96)


def _gen_table():
    # TODO
    pass


if __name__ == '__main__':
    pass
