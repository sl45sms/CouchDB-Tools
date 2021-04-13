#!/usr/bin/env python3
import uuid
from itertools import starmap
from operator import xor
from struct import Struct
import hashlib
import hmac
from binascii import hexlify
import sys

def bytes_(s, encoding='utf8', errors='strict'):
    if isinstance(s, str):
        return s.encode(encoding, errors)
    return s

def hexlify_(s):
    return str(hexlify(s), encoding="utf8")

def range_(*args):
    return range(*args)

def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(bytes_(data), None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(bytes_(x))
        return [x for x in h.digest()]
    buf = []
    _pack_int = Struct('>I').pack
    for block in range_(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(bytes_(salt) + _pack_int(block))
        for i in range_(iterations - 1):
            u = _pseudorandom(bytes(u))
            rv = starmap(xor, zip(rv, u))
        buf.extend(rv)
    return bytes(buf)[:keylen]

def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return hexlify_(pbkdf2_bin(data, salt, iterations, keylen, hashfunc))

def generate_hash(username, password):
    """
    generates a pbkdf2 password hash to use on couchdb admins
    :param password: Password for couchdb cluster admin
    :type password: str
    :rtype: None
    """
    pbkdf2=""
    salt=uuid.uuid4().hex
    iterations=10
    pbkdf2 = "-pbkdf2-{},{},{}".format(pbkdf2_hex(password,salt,iterations,20),salt,iterations)
    return pbkdf2

try:
  print (generate_hash(sys.argv[1],sys.argv[1]))
except IndexError:
  print("Usage: genHash.py password")
