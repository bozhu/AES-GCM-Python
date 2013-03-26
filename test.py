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
    'plaintext': b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                 b'\x00\x00\x00\x00\x00\x00\x00\x00',
    'auth_data': b'',
    'init_value': 0x000000000000000000000000,
    'ciphertext': b'\x03\x88\xda\xce\x60\xb6\xa3\x92' +
                  b'\xf3\x28\xc2\xb9\x71\xb2\xfe\x78',
    'auth_tag': 0xab6e47d42cec13bdf53a67b21257bddf,
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
            print 'One test case failed!'
            pprint(test_data)
            print

    if num_failures == 0:
        print 'All test cases passed!'
    else:
        print num_failures, 'test cased failed!'
