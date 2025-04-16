"""
EXP For expired_sub, pirated_sub, recording_playback, and no_sub.
author: Xinyue
Description: Target use hardcoded credential
"""
import struct
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def derive_key(secret: bytes, offset: int) -> bytes:
    return hmac.new(secret[offset:], secret, hashlib.sha256).digest()

# --- 1. Setup keys and encrypted data

# Taken from secrets.h
# secret_hex = "415a4ae674bdf4d45b44e81ffdb60cb71bf4753cc3d5c60534671c3fd58547f2c17c0b89a0021f1821930e15509fb99e"
# secret = bytes.fromhex(secret_hex)

kve = bytes.fromhex("4ca5da570556a805aa26e9160d8a35862175225baa963e332196583f6eef61ae")
kva = bytes.fromhex("d33efa98b34fbdc2e797004f473352371ada29f88c2d4e16710fb2d030d6dfca")

# Captured frame (ciphertext + hmac)
frame = b"\xc9\t\x97\x194.\xdc\x94\xc3cW\xa7\xa8e\xb7\xa4\xf4\xe3%tU\x91S\xdcO\x03\xf6W\xbb\xa0\xbf\x95y\x01\xf4_\x11\x06\xabC\xa9\x85w\xe8\xc6\x00[%\xb8\x84=s\x98/\x7f\x93\xf1g\xf4\xb4\xca\x10\x02\xd7r\xbf9\xa2b\xa9\x81k\x9a\xad\x14GR IG\t\x96m\xfbN\x9c\xf9\xb1\x9e\x15c\xbb\x92a\x87g\xa1\xf2,5\xe6\xd0\xce{e\x89\xc3\xe9\xc0\xfdAb\x87\xf2b5\xb8\xe5\x9d\x1f\xa9\x93b)\xb9+\x16\x7fav$J\r @B\x86\x14\xd1\xeb\xec\x1b\xbd'\x88u\x8f\xee\xaa\xc0G\x10\x99S\xb3a\xbc\x873\xc6\xafAp\x1f\xbcm\xc0\x9c\xb1\xf8\xfd:\xc0\xf3ZR"
#for recording playback
# frame = bytes.fromhex("fc9ae571bf0807198eb062874b128733647bca01e55e72dcc304a044bcf467b0ef13c07af35fbd6a2c02723bcdbc1abdf3865241511c413b003a9a25f79b211f7ca42e3eb91789432cc3d4fac8517cdc7b9a267c6fa26d52a582362d8b351bf3eeec07525ababcbc6c134b978cbe8a57f2ba911595d5426b2a79fefb7e8dc692380ed69f9aaa0ce06f68fac1910e957d5c3ae1ea66370298569564778eb9f69bd0c7ff003098d852e10b4affd626184f")
ciphertext = frame[:-32]
hmac_received = frame[-32:]

# --- 2. Verify HMAC
hmac_calculated = hmac.new(kva, ciphertext, hashlib.sha256).digest()
if hmac_calculated != hmac_received:
    print("❌ HMAC check failed.")
    print("Expected:", hmac_received.hex())
    print("Got     :", hmac_calculated.hex())
    exit(1)

print("✅ HMAC check passed.")

# --- 3. Extract channel and timestamp from decrypted block

# IV = first 4 bytes of ciphertext (encrypted channel+timestamp block) + kve[:12]
iv = ciphertext[0:4] + kve[:12]
cipher = AES.new(kve, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)

print(decrypted)

# remove padding
try:
    decrypted = unpad(decrypted, AES.block_size)
except ValueError:
    print("Unpad failed. Incorrect padding or bad decryption.")
    exit(1)

# --- 4. Extract metadata
channel, timestamp = struct.unpack("<IQ", decrypted[:12])
encoded_frame = decrypted[12:]

print(f"Channel: {channel}")
print(f"Timestamp: {timestamp}")

# --- 5. Decode RLE
def rle_decode(data: bytes) -> bytes:
    if len(data) < 2:
        return b""
    expected_len = data[0] | (data[1] << 8)
    out = bytearray()
    for i in range(2, len(data), 2):
        count = data[i]
        value = data[i + 1]
        out.extend([value] * count)
    return bytes(out[:expected_len])

decoded = rle_decode(encoded_frame)
print("Decoded Frame:", decoded.decode(errors='replace'))
