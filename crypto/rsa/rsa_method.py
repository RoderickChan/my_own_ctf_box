# coding:utf-8

import gmpy2
from typing import Tuple
import sympy
import random
from functools import reduce
from Crypto.Util.number import long_to_bytes, bytes_to_long


def get_pq_from_n_ed(n, ed):
    '''
    根据n e d求解p 和 q
    :param n: 模数
    :param ed: ed的积
    :return: p, q

    '''
    p = 1
    q = 1
    while p == 1 and q == 1:
        k = ed - 1
        g = random.randint(0, n)
        while p == 1 and q == 1 and k % 2 == 0:
            k = k // 2
            y = pow(g, k, n)
            if y != 1 and gmpy2.gcd(y - 1, n) > 1:
                p = gmpy2.gcd(y - 1, n)
                q = n // p
    return p, q

def get_pq_from_n_e_d(n, e, d):
    '''
    根据n e d求解p 和 q
    :param n: 模数
    :param e: 公钥
    :param d: d
    :return: p, q
    '''
    return get_pq_from_n_ed(n, e*d)

def crt_attack(nl: list, cl:list) -> int:
    '''
    多组明文广播攻击，利用中国剩余定理

    :param nl: 模数列表
    :param cl: 明文列表
    :param e: 公钥
    :return:int
    '''
    assert (reduce(gmpy2.gcd, nl) == 1)
    assert (isinstance(nl, list) and isinstance(cl, list))
    M = reduce(lambda x, y: x * y, nl)
    ai_ti_Mi = [a * gmpy2.c_div(M, m) * gmpy2.invert(gmpy2.c_div(M, m), m) for (m, a) in zip(nl, cl)]
    tmp = reduce(lambda x, y: x + y, ai_ti_Mi) % M
    return tmp

def crt_attack_not_coprime(n_list : list, c_list: list) -> Tuple:
    '''
    中国剩余定理，模数不互质的时候的解
    :param n_list: 模数列表
    :param c_list: 明文列表
    :return: (int, int)--->(解,最小公倍数)
    '''
    assert (isinstance(n_list, list) and isinstance(c_list, list))
    curm, cura = n_list[0], c_list[0]
    for (m, a) in zip(n_list[1:], c_list[1:]):
        d = gmpy2.gcd(curm, m)
        c = a - cura
        assert (c % d == 0) #不成立则不存在解
        K = c // d * gmpy2.invert(curm // d, m // d)
        cura += curm * K
        curm = curm * m // d
    return (cura % curm, curm)

def common_n_attack(c1, e1, c2, e2, n):
    _,x,y = gmpy2.gcdext(e1, e2)
    if x < 0:
        x = -x
        c1 = gmpy2.invert(c1, n)
    if y < 0:
        y = -y
        c2 = gmpy2.invert(c2, n)
    return long_to_bytes(gmpy2.powmod(c1, x, n) * gmpy2.powmod(c2, y, n) % n)
