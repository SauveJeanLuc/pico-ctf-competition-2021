#!/usr/bin/python

from binascii import hexlify
from gmpy2 import mpz_urandomb, next_prime, random_state
import math
import os
import sys

if sys.version_info < (3, 9):
    import gmpy2
    math.gcd = gmpy2.gcd
    math.lcm = gmpy2.lcm

FLAG  = open('flag.txt').read().strip()
FLAG  = int(hexlify(FLAG.encode()), 16)
SEED  = int(hexlify(os.urandom(32)).decode(), 16)
STATE = random_state(SEED)

def get_prime(bits):
    return next_prime(mpz_urandomb(STATE, bits) | (1 << (bits - 1)))

p = get_prime(1024)
print("Public key (p): "+ str(p))
q = get_prime(1024)
print("Public key (q): "+ str(q))

x = p + q
print("(x): "+ str(q))
n = p * q
print("(n): "+ str(q))

e = 65537

m = math.lcm(p - 1, q - 1)

print("(m): "+ str(m))
d = pow(e, -1, m)
print("(d): "+ str(d))

c = pow(FLAG, e, n)
print("Start of real C: ")
print(c)
print("End of real C")

print(f'x = {x:x}')
print(f'n = {n:x}')
print(f'c = {c:x}')
