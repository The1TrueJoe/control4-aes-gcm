# control4-aes-gcm

AES-128-GCM for Control4 DriverWorks drivers (Lua 5.1), built on Director's own AES-ECB.

Director's crypto API (`C4:Encrypt`) has ECB and CBC but no GCM. GCM is counter mode plus a
GHASH tag, so `aes_gcm.lua` builds it from ECB: the keystream is a single native
`C4:Encrypt` over all the counter blocks, then an XOR; GHASH runs in Lua.

```lua
-- key: 16 bytes, nonce: 12 bytes, no associated data
local sealed = AesGcm.encrypt(key, nonce, plaintext)          -- ciphertext .. 16-byte tag
local plain  = AesGcm.decrypt(key, nonce, sealed)             -- nil if the tag doesn't match
local plain  = AesGcm.decrypt(key, nonce, sealed, { verify = false })
```

`aes_gcm.lua` is one self-contained file: add it to your driver (concatenate it or `require`
it) and nothing else is needed but `C4:Encrypt`.

## Cost

The keystream is native. GHASH is about 600 XORs per 16 bytes in Lua, so checking the tag of
a large message (tens of KB) takes a noticeable moment on an older controller. For data that
already arrived over a verified channel such as Director's HTTPS, `verify = false` skips it.
It uses `bit32` or LuaBitOp's `bit` when Director provides one (an EA-1 on OS 3.3 does), and
table-driven XOR otherwise.

## Testing

```sh
pip install lupa cryptography
python3 test/test_aes_gcm.py
```

Checks every result against Python's AES-GCM, with and without a bit library, including
empty and non-block-sized messages and a tampered message.

Used by: [control4-tuya](https://github.com/The1TrueJoe/control4-tuya) (the Tuya Bridge's Smart Life sign-in).
