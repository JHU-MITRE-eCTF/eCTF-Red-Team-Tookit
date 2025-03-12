"""Zhong: no subscription exp for SEMO"""
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

Cracker().decode(b'\x1b_\x1ci\x1bB&\xb7\x1bp\xc3\xa79\xb7\xb2\xbar\xab\x0b}\xc2\xf1\xad\x02\xb3.\x7fB\xdd\xa2=\x9f\x01Oo\xf5\x81\\\xe0\x10\xe2\xee\xee\x19\xd1\x03\xca94\xffI\xbbI\xab-\x93:,\xe7\xe0g<\xfa\x81w\x1bP\x04\xf1\x82\x90\xef\x81\x15&\xff\xf89\x87\xaeCc\xaf\xb8 \xb5<\xf4\xb8\xbb\x14\xb7*n\x16\x98')