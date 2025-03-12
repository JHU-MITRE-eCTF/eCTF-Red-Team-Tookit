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

Cracker().decode(bytes.fromhex('a0305f28855fcdca3d8f60f1c47e8ce11a3b4cfae36dfcb4d0d549238786dd79216ae083c2fe6e0c506d2de4ce4dfbef188587422b0d4975731c01ea24c74451c6757f5ebe60b8babda126316f4e8b325ee79cca9aaea5f0c73931bcd75fd5aa'))