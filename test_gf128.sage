#!/usr/bin/env sage

B.<x> = GF(2)[]
F.<a> = GF(2 ^ 128, modulus=x ^ 128 + x ^ 7 + x ^ 2 + x + 1)


def int2ele(integer):
    res = 0
    deg = 0
    while integer > 0:
        res += (integer & 1) * (a ^ deg)
        integer >>= 1
        deg += 1
    return res


def ele2int(element):
    return element.integer_representation()


def gf128_mul_correct(x1, x2):
    return ele2int(int2ele(x1) * int2ele(x2))


from aes_gcm import gf128_mul as gf128_mul_to_verify

from random import getrandbits

for i in range(1000):
    x = getrandbits(128)
    h = getrandbits(128)
    assert gf128_mul_to_verify(x, h) == gf128_mul_correct(x, h)

print 'All tests passed!'
