#!/usr/bin/env sage

"""
    Copyright (C) 2013 Bo Zhu http://about.bozhu.me

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""

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


def gf_2_128_mul_correct(x1, x2):
    return ele2int(int2ele(x1) * int2ele(x2))


from aes_gcm import gf_2_128_mul as gf_2_128_mul_to_verify


if __name__ == '__main__':
    from os import urandom
    from Crypto.Util.number import bytes_to_long

    for i in range(1000):
        x = bytes_to_long(urandom(16))  # 16 bytes
        h = bytes_to_long(urandom(16))
        assert gf_2_128_mul_to_verify(x, h) == gf_2_128_mul_correct(x, h)

    print '1000 random test cases passed!'
