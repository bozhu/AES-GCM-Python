#!/usr/bin/env sage

BF.<X> = GF(2)[]
FF.<A> = GF(2 ^ 128, modulus=X ^ 128 + X ^ 7 + X ^ 2 + X + 1)


def int2ele(integer):
    res = 0
    for i in range(128):
        # rightmost bit is x127
        res += (integer & 1) * (A ^ (127 - i))
        integer >>= 1
    return res


def ele2int(element):
    integer = element.integer_representation()
    res = 0
    for i in range(128):
        res = (res << 1) + (integer & 1)
        integer >>= 1
    return res


def gf128_mul_correct(x1, x2):
    return ele2int(int2ele(x1) * int2ele(x2))


from aes_gcm import gf128_mul as gf128_mul_to_verify


if __name__ == '__main__':
    from random import getrandbits

    for i in range(1000):
        x = getrandbits(128)
        h = getrandbits(128)
        assert gf128_mul_to_verify(x, h) == gf128_mul_correct(x, h)

    print '1000 random test cases passed!'
