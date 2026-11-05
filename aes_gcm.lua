-- AES-128-GCM for Control4 DriverWorks drivers, built on Director's AES-ECB.
--
-- Director's crypto API (C4:Encrypt) offers ECB/CBC but no GCM. GCM is counter mode plus a
-- GHASH tag, so this builds it from ECB: the whole keystream is one native C4:Encrypt over
-- the counter blocks, then an XOR; GHASH runs in Lua.
--
--   local sealed = AesGcm.encrypt(key, nonce, plaintext)   -- ciphertext .. 16-byte tag
--   local plain  = AesGcm.decrypt(key, nonce, sealed)      -- nil if the tag doesn't match
--   local plain  = AesGcm.decrypt(key, nonce, sealed, { verify = false })
--
-- key: 16 bytes (AES-128). nonce: 12 bytes. No associated data.
--
-- Cost: the keystream is native; GHASH is ~600 XORs per 16 bytes in Lua. Checking the tag of
-- a large message (tens of KB) takes a noticeable moment on an older controller. When the
-- data already came over a verified channel (Director's HTTPS), `verify = false` skips it.
--
-- Uses Lua's `bit32` or LuaBitOp `bit` when present, otherwise table-driven XOR. Lua 5.1.

AesGcm = AesGcm or {}

local TWO32 = 4294967296

local BXOR
if (type(bit32) == 'table' and bit32.bxor) then
	BXOR = function(a, b) return bit32.bxor(a, b) % TWO32 end
elseif (type(bit) == 'table' and bit.bxor) then
	BXOR = function(a, b) return bit.bxor(a, b) % TWO32 end
else
	local NIBBLE = {}
	for x = 0, 15 do
		for y = 0, 15 do
			local r, p, a, b = 0, 1, x, y
			for _ = 1, 4 do
				if (a % 2 ~= b % 2) then r = r + p end
				a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
			end
			NIBBLE[x * 16 + y] = r
		end
	end
	BXOR = function(a, b)
		local result, place = 0, 1
		while (a > 0 or b > 0) do
			local x, y = a % 16, b % 16
			result = result + NIBBLE[x * 16 + y] * place
			a, b, place = (a - x) / 16, (b - y) / 16, place * 16
		end
		return result
	end
end

local function U32(n)
	n = n % TWO32
	return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function ReadU32(s, i)
	local a, b, c, d = string.byte(s, i, i + 3)
	return ((a * 256 + b) * 256 + c) * 256 + d
end

local function XorStrings(a, b)
	local out = {}
	for i = 1, math.min(#a, #b) do
		out[i] = string.char(BXOR(string.byte(a, i), string.byte(b, i)))
	end
	return table.concat(out)
end

local RAW = { return_encoding = 'NONE', key_encoding = 'NONE', iv_encoding = 'NONE', data_encoding = 'NONE', padding = false }

-- ECB takes no IV, and Director refuses one ("The specified iv was too long").
local function Ecb(key, data)
	local out, err = C4:Encrypt('AES-128-ECB', key, '', data, RAW)
	if (not out) then
		error('AES-128-ECB failed: ' .. tostring(err))
	end
	return out
end

-- GF(2^128) multiply (NIST SP 800-38D, algorithm 1) on four 32-bit words, most significant first.
local function GfMul(x, y)
	local z1, z2, z3, z4 = 0, 0, 0, 0
	local v1, v2, v3, v4 = y[1], y[2], y[3], y[4]
	for w = 1, 4 do
		local word = x[w]
		for bitIndex = 31, 0, -1 do
			if (math.floor(word / 2 ^ bitIndex) % 2 == 1) then
				z1, z2, z3, z4 = BXOR(z1, v1), BXOR(z2, v2), BXOR(z3, v3), BXOR(z4, v4)
			end
			local lsb = v4 % 2
			v4 = math.floor(v4 / 2) + (v3 % 2) * 2147483648
			v3 = math.floor(v3 / 2) + (v2 % 2) * 2147483648
			v2 = math.floor(v2 / 2) + (v1 % 2) * 2147483648
			v1 = math.floor(v1 / 2)
			if (lsb == 1) then
				v1 = BXOR(v1, 0xE1000000)
			end
		end
	end
	return { z1, z2, z3, z4 }
end

local function Words(block)
	return { ReadU32(block, 1), ReadU32(block, 5), ReadU32(block, 9), ReadU32(block, 13) }
end

local function Ghash(h, data)
	local hw = Words(h)
	local y = { 0, 0, 0, 0 }
	for i = 1, #data, 16 do
		local b = Words(string.sub(data, i, i + 15))
		y = GfMul({ BXOR(y[1], b[1]), BXOR(y[2], b[2]), BXOR(y[3], b[3]), BXOR(y[4], b[4]) }, hw)
	end
	return U32(y[1]) .. U32(y[2]) .. U32(y[3]) .. U32(y[4])
end

-- Counter mode from counter block 2 on (block 1 masks the tag), in one native call.
local function Ctr(key, nonce, data)
	if (#data == 0) then return '' end
	local blocks = {}
	for i = 1, math.ceil(#data / 16) do
		blocks[i] = nonce .. U32(i + 1)
	end
	local stream = Ecb(key, table.concat(blocks))
	return XorStrings(data, string.sub(stream, 1, #data))
end

local function Tag(key, nonce, cipher)
	local h = Ecb(key, string.rep('\0', 16))
	local padded = cipher .. string.rep('\0', (16 - #cipher % 16) % 16)
	local lengths = U32(0) .. U32(0) .. U32(math.floor(#cipher * 8 / TWO32)) .. U32(#cipher * 8)
	return XorStrings(Ghash(h, padded .. lengths), Ecb(key, nonce .. U32(1)))
end

local function Check(key, nonce)
	if (type(key) ~= 'string' or #key ~= 16) then error('AesGcm: key must be 16 bytes') end
	if (type(nonce) ~= 'string' or #nonce ~= 12) then error('AesGcm: nonce must be 12 bytes') end
end

--- Encrypts and seals. Returns ciphertext .. 16-byte tag.
function AesGcm.encrypt(key, nonce, plain)
	Check(key, nonce)
	local cipher = Ctr(key, nonce, plain or '')
	return cipher .. Tag(key, nonce, cipher)
end

--- Opens ciphertext .. tag. Returns the plaintext, or nil if the tag doesn't match.
--- options.verify = false skips the tag check (see the cost note above).
function AesGcm.decrypt(key, nonce, sealed, options)
	Check(key, nonce)
	if (type(sealed) ~= 'string' or #sealed < 16) then return nil end
	local cipher = string.sub(sealed, 1, #sealed - 16)
	if (not (options and options.verify == false)) then
		if (Tag(key, nonce, cipher) ~= string.sub(sealed, -16)) then
			return nil
		end
	end
	return Ctr(key, nonce, cipher)
end
