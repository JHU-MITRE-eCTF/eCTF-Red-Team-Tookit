import time
import sys
import struct

# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)

    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])

    # Send reference design frames
    # ```
    # return struct.pack("<IQ", channel, timestamp) + frame
    # ```
    interface.decode(struct.pack("<IQ", 1, 1) + b"hello world")

    print("Done with pesky Neighbor attack")
