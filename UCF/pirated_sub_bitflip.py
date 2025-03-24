"""Expired Subscription Attack for UCF
@author: Liz Grzyb
@description: UCF uses AES CBC without authentication, and the IV is sent in plaintext. Here we use the IV to flip bits in the device ID field of 
a subscription packet to alter the pirated subscription to correct ID.
"""

import struct

def flip_device_id_in_iv(original_iv: bytes, old_device_id: int, new_device_id: int) -> bytes:
    """Flip the first 4 bytes of the IV to change the device_id."""
    iv = bytearray(original_iv)

    old_bytes = struct.pack("<I", old_device_id)
    new_bytes = struct.pack("<I", new_device_id)

    print("[+] Flipping IV bytes to change device_id:")
    for i in range(4):
        delta = old_bytes[i] ^ new_bytes[i]
        iv[i] ^= delta
        print(f"    IV[{i}] ^= 0x{delta:02x}  (byte {i}: {old_bytes[i]:02x} → {new_bytes[i]:02x})")

    return bytes(iv)

def modify_device_id(filename: str, output_filename: str, old_device_id: int, new_device_id: int):
    with open(filename, "rb") as f:
        data = f.read()

    assert len(data) == 52, "Subscription packet must be exactly 52 bytes"

    channel = data[0:4]
    iv = data[4:20]
    ciphertext = data[20:]

    new_iv = flip_device_id_in_iv(iv, old_device_id, new_device_id)

    new_packet = channel + new_iv + ciphertext

    with open(output_filename, "wb") as f:
        f.write(new_packet)

    print(f"[+] Saved modified subscription with new device ID to: {output_filename}")

# === CONFIG ===

original_device_id = 0x6f698f63
target_device_id   = 0x42f52b16

modify_device_id("pirated.sub", "pirated_newid.sub", original_device_id, target_device_id)
