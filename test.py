#!/usr/bin/env python

from aes_gcm import AES_GCM
from pprint import pprint

test_cases = ({
    'master_key': 0x00000000000000000000000000000000,
    'plaintext': b'',
    'auth_data': b'',
    'init_value': 0x000000000000000000000000,
    'ciphertext': b'',
    'auth_tag': 0x58e2fccefa7e3061367f1d57a4e7455a,
}, {
    'master_key': 0x00000000000000000000000000000000,
    'plaintext':  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    'auth_data':  b'',
    'init_value': 0x000000000000000000000000,
    'ciphertext': b'\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78',
    'auth_tag':   0xab6e47d42cec13bdf53a67b21257bddf,
}, {
    'master_key': 0x7fddb57453c241d03efbed3ac44e371c,
    'plaintext':  b'\xd5\xde\x42\xb4\x61\x64\x6c\x25\x5c\x87\xbd\x29\x62\xd3\xb9\xa2',
    'auth_data':  b'',
    'init_value': 0xee283a3fc75575e33efd4887,
    'ciphertext': b'\x2c\xcd\xa4\xa5\x41\x5c\xb9\x1e\x13\x5c\x2a\x0f\x78\xc9\xb2\xfd',
    'auth_tag': 0xb36d1df9b9d5e596f83e8b7f52971cb3,
})


if __name__ == '__main__':
    num_failures = 0

    for test_data in test_cases:
        test_gcm = AES_GCM(test_data['master_key'])
        cipher, tag = test_gcm.encrypt(
            test_data['init_value'],
            test_data['plaintext'],
            test_data['auth_data']
        )

        if cipher != test_data['ciphertext'] or tag != test_data['auth_tag']:
            num_failures += 1
            print 'This test case failed:'
            pprint(test_data)
            print

    if num_failures == 0:
        print 'All test cases passed!'
    else:
        print num_failures, 'test cases failed in total.'
