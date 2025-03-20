"""Pesky Neighbor attack for UCI
@author: Gavin Zhong
@description: UCI encodes frame using AES-CBC which is vulnerable to bit flipping attack.
"""
import time
import sys
# The ectf25 module comes pre-installed in the environment
from ectf25.utils.decoder import DecoderIntf


if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    time.sleep(1)
    
    # The serial port string will be in argv[1]
    interface = DecoderIntf(sys.argv[1])
    # Send flipped frame
    interface.decode(b'\x01\x00\x00\x00\xb9\xf1\xe8\x94\x9bL\x07\x00@\x00\x00\x00\xca\xbc\x17\xdd*j\xea\x96\x99~M\xc9\xe59\x13+\xb6\xde\xdf\x0f\x0c\x15\xf5Y\xb54\xa0\x80\x06\xad\xb5\xfc7\xa9\xa0Z\x96$\xb1\x92\x81\xe2\xc6\xfc\xe8\xcf\x07\xd0\xcf\x042\x02\xf7\xa8\xe2\x8d\xdb&\x0b\xf3"\x1f\xca\x83Nt\xb5/|)V\xe8\xade\xd9\xd7\xa0X\n\xfa\x00\x87\r9\x06\xf5\xc0\xcc78g\xde\xd1\xaf\xeec\xac\xa1\xe7Y\x03~:T\xb1"\xd9\xaf\x85:\xde\xf4')

    print("Done with pesky Neighbor attack")
