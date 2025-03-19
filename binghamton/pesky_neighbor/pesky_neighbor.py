"""Pesky Neighbor attack for binghamton
@author: Gavin Zhong
@description: binghamton encodes frame using AES-ECB which encrypt each 16 byte chunk independently
by shuffling the 16 byte chunks, we tampers the order of the clear text decrypted.
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def misorder_frame_channel1():
    """Gavin Zhong
        Misorder 16 byte chunks of lgmt encoded frames except for first 
        and the last 16 bytes, which are the header and potentially padded bytes
    """
    lgmt_frame_channel1 = b't&\xcc\x80$\xb5\x1b({\xaf`\t\x17U\x18\xcd\xf8\x12\xac\xb4\x99\xeb\x8ag\xe9\xe9\xc3}\xce\x86\xd0\xf1\xa6\xe4@F+>\xaa\xdd\xe2\xc2\xde\x19\x02\xfc\x84l\xc5L\x7fZ\xeb\x1c(\xa4\xc1\'"\xda\xeeT\xc6\x804\x96nI\x9e\x01\x86\xa26\x06\xa5\xa2\xe5L\xb2\n'
    # split into 16 bytes chunks
    chunks = [lgmt_frame_channel1[i:i + 16] for i in range(0, len(lgmt_frame_channel1), 16)]
    # randomly misorder the chunks except first and last
    def _shuffle_slices(chunks_sliced: list[bytes]) -> list[bytes]:
        import random
        random.shuffle(chunks_sliced)
        return chunks_sliced
    return b''.join([chunks[0]] + _shuffle_slices(chunks[1:-1]) + [chunks[-1]])


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Send 16-byte shuffled encoded frame
    interface.decode(misorder_frame_channel1())

    print("Done with pesky Neighbor attack")
