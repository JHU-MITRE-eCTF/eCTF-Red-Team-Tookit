"""Zhong: pirated subscription exp for SEMO"""
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Cracker:
    def __init__(self):
        secrets = {
        "aes_key": "24f6754364b954cfb33671c831da582edb88b942442357d9c95ae94e9f8fe20d",
        "cbc_iv": "c6d30c124fbe47e86a02fc2a64b230bf"
        }
        self.aes_key = bytes.fromhex(secrets["aes_key"])
        self.cbc_iv = bytes.fromhex(secrets["cbc_iv"])  # type: ignore

    def decode(self, encrypted_frame: bytes) -> tuple[int, bytes, int]:
        """The frame decoder function

        This function reverses the encoding process to extract the original channel number,
        frame data, and timestamp.

        :param encrypted_frame: The encrypted frame received from the Encoder.
        :returns: A tuple containing:
            - channel (int): The 32-bit unsigned channel number.
            - frame (bytes): The original frame data.
            - timestamp (int): The original 64-bit timestamp.
        """
        TOTAL_FRAME_SIZE = 64

        # Decrypt the frame
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.cbc_iv))
        decryptor = cipher.decryptor()
        decrypted_frame = decryptor.update(encrypted_frame) + decryptor.finalize()
        print(decrypted_frame)
        # # Unpack the frame components
        # channel, _reserved1, timestamp, pad_len, _reserved2 = struct.unpack("<I4xQI12x", decrypted_frame[:32])

        # # Extract the actual frame data (excluding padding)
        # frame = decrypted_frame[24:-pad_len] if pad_len else decrypted_frame[24:]

        # return channel, frame, timestamp

Cracker().decode(b"\xe6C\xa9\xa5\x82\x97_j\x96\xcb\xa36?E\x88~\xb0\x16\xdd\x1b\xac\x87\x1b8\x83j{h\xd2\x07\x9eH\x8e\\\xc9\x18\xdch\xc7\xb5\nu&\x83\x15W\x08\xde(f*E\xedNA\xdb\xcfo(\xf7'R'%*2\xe1\xc8\x07\xf4\x83\x18dS\x9c\xad\xf2\xd5v\x10k\xf6@\xb3O1\x01c\xe2\xdbI\x1a\xc6\x85\xd0\xfb")