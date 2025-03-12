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

Cracker().decode(b'm\xa9\x1e\xa7\x8fn)Q5\x0c\xb5\x8b\xedJ\xf5\x9f\xf8\x7f\x8e\xc1^\x1d+\xf8\x8d|\xb2\x9b\x89\xa9\x81\xc7\xa1\xa4\xa8\xed\xae\xdbG.!\x1d\x98\xb2e\r,{\xce\x12\x9a\xc3\xa52\xb5\xf4\xd7\xe43<\x84\xb7\x85&\x83\x87)M\xe1\xb7\xc4\x1d\x00\x8e@\x8f\n\xe9n\x9a\x94\xc1Dj\xfbW;9\x8c\x1bi!\x0c\x9e:O')