"""Checks aes_gcm.lua against Python's AES-GCM (the `cryptography` package), in Lua 5.1.

    pip install lupa cryptography && python3 test/test_aes_gcm.py

C4:Encrypt is stood in for by an AES-128-ECB that, like Director, refuses an IV.
Runs with and without a bit library, since Director may or may not provide one.
"""

import os
import sys
import time

import lupa.lua51 as lua51
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aes_gcm.lua")


def runtime(with_bit):
    lua = lua51.LuaRuntime(encoding=None, unpack_returned_tuples=True)

    def encrypt(_, cipher, key, iv, data, opts=None):
        if cipher != b"AES-128-ECB":
            return None, b"unsupported cipher"
        if iv:
            return None, b"The specified iv was too long"
        if len(data) % 16:
            return None, b"data not a multiple of the block size"
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return enc.update(data) + enc.finalize()

    lua.globals().C4 = lua.table_from({b"Encrypt": encrypt})
    if with_bit:
        # A LuaBitOp-shaped `bit`: signed 32-bit results, as Director's is.
        lua.execute(b"bit = { bxor = function(a, b) local r, p = 0, 1 "
                    b"a = a % 4294967296 b = b % 4294967296 "
                    b"while a > 0 or b > 0 do local x, y = a % 2, b % 2 if x ~= y then r = r + p end "
                    b"a = (a - x) / 2 b = (b - y) / 2 p = p * 2 end "
                    b"if r >= 2147483648 then r = r - 4294967296 end return r end }")
    lua.execute(open(LIB, "rb").read())
    return lua, lua.globals().AesGcm


def main():
    failures = 0
    for with_bit in (False, True):
        lua, gcm = runtime(with_bit)
        no_verify = lua.table_from({b"verify": False})
        for n in (0, 1, 15, 16, 17, 31, 33, 100, 1000, 4096):
            key, nonce, plain = os.urandom(16), os.urandom(12), os.urandom(n)
            want = AESGCM(key).encrypt(nonce, plain, None)
            got = gcm.encrypt(key, nonce, plain)
            opened = gcm.decrypt(key, nonce, want)
            fast = gcm.decrypt(key, nonce, want, no_verify)
            if got != want or opened != plain or fast != plain:
                failures += 1
                print(f"FAIL n={n} bit={with_bit}")
        # A tampered tag or ciphertext is refused.
        key, nonce = os.urandom(16), os.urandom(12)
        sealed = bytearray(AESGCM(key).encrypt(nonce, b"hello, director", None))
        sealed[0] ^= 1
        if gcm.decrypt(key, nonce, bytes(sealed)) is not None:
            failures += 1
            print(f"FAIL tamper bit={with_bit}")
        t = time.time()
        gcm.decrypt(key, nonce, AESGCM(key).encrypt(nonce, os.urandom(30000), None))
        print(f"{'bit' if with_bit else 'table XOR'}: 30 KB verified decrypt {1000 * (time.time() - t):.0f} ms on this machine")
    print("PASS" if failures == 0 else f"{failures} FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
