"""
  @author: Gavin Zhong
  @date: 2025 03/19
  @affiliation: JHU MSSI
  @license: MIT
"""
from dataclasses import dataclass
import struct
from ectf25.utils.decoder import DecoderIntf

@dataclass
class EncodedFrame:
  # 4 bytes
  channel: int
  # 8 bytes
  timestamp: int
  # 4 bytes
  frame_size: int
  # 16 bytes
  IV: bytes
  # 32 bytes timestamp 8-byte nonce + 8-byte timestamp + 8-byte nonce + 8-byte padding
  cipher_text_1: bytes
  # 64 bytes frame
  cipher_text_2: bytes

  
  struct_format = '<IQI16s32s64s'
    
  def to_bytes(self) -> bytes:
    return struct.pack(self.struct_format, self.channel, self.timestamp, self.frame_size, self.IV, self.cipher_text_1, self.cipher_text_2)
  
  @classmethod
  def from_bytes(cls, data: bytes) -> 'EncodedFrame':
    channel, timestamp, frame_size, IV, cipher_text_1, cipher_text_2 = struct.unpack(cls.struct_format, data)
    return cls(channel, timestamp, frame_size, IV, cipher_text_1, cipher_text_2)
  
class ExpiredSubWrapper:
  """ 
    @author: Gavin Zhong
    @date: 2025 03/19
    @affiliation: JHU MSSI
    @license: MIT
    @description: this attacker wrapper is written to exploit the encryption vulnerability in
      UCI's design. UCI incorrectly uses the AES-CBC mode to secure the timestamp without HMAC.
  """
  def __init__(self, lgtm_frame_data: bytes):
    """ 
      @param lgtm_frame_data: The legitimate frame data
    """
    self.frame = self._sub_wrapper(lgtm_frame_data)
      
  def _sub_wrapper(self, lgtm_frame_data: bytes) -> EncodedFrame:
    """ Wrap subscription file into a EncodedFrame object """
    return EncodedFrame.from_bytes(lgtm_frame_data)

  def _falsify_frame_timestamp(self, current_frame_timestamp: int, falsified_frame_timestamp: int) -> bytes:
    """ The first encrypted 16-byte block for the encoded frame is 
    ENC(8-byte nonce + 8-byte timestamp)
    
    * Given the fact:
      * plaintext is derived by XOR(IV, cur_decrypted_cipher_block) at the first block
      * We have the access to `IV` and the 8-byte `timestamp` in clear-text of the first block
      
    * So we can falsify timestamp of the message
    * by 
      * First, calculate the cur_decrypted_cipher_block[8:] by XOR(IV[8:], timestamp)
      * Then, we can calculate the new IV by XOR(cur_decrypted_cipher_block[8:], falsified_timestamp)
      * Finally, flipping the bits of `IV` to the new IV, which leads to the forged data decryption.
    * 
    
    ** However, we can not randomly falsify the timestamp, since the IV is also used to encrypt the frame data;
      * We know the fact that single flip of a bit in the IV will lead to a single flip of a bit in the decrypted frame data.
      * We only flip one highest bit of the current frame's timestamp from 1 to 0 to downgrade the frame's timestamp.
      * So that the decrypted frame data will only be one bit flipped and can be easily recovered
      
    * 
    AES-CBC Decryption Scheme: https://alicegg.tech/assets/2019-06-23-aes-cbc/bit_flipping.jpg
    """
    # def __flip_highest_bit(n: int) -> int:
    #   """Flips the most significant (highest) 1-bit to 0."""
    #   if n == 0:
    #       return 0  # No bits to flip
    #   highest_bit = n.bit_length() - 1  # Find the position of the highest set bit
    #   mask = 1 << highest_bit  # Create a mask for that bit
    #   return n ^ mask  # XOR to flip that bit
  
    cur_decrypted_cipher_block = bytes(x ^ y for x, y in zip(self.frame.IV[8:], struct.pack("<Q", current_frame_timestamp)))
    new_IV = self.frame.IV[:8] + \
      bytes(x ^ y for x, y in zip(cur_decrypted_cipher_block, struct.pack("<Q", falsified_frame_timestamp)))
    print(f"old IV: {self.frame.IV.hex()} -> new IV: {new_IV.hex()}")
    print(f"old IV: {bin(int(self.frame.IV.hex(), 16))} -> new IV: {bin(int(new_IV.hex(), 16))}")

    self.frame.IV = new_IV
    print(f"old timestamp: {self.frame.timestamp} -> new timestamp: {falsified_frame_timestamp}")

    self.frame.timestamp = falsified_frame_timestamp
    
    return self.frame.to_bytes()
  
  def _flipped_frame(self) -> bytes:
    self.frame.cipher_text_2 = self.frame.cipher_text_2[:32] + b'\x00' + self.frame.cipher_text_2[33:]
    return self.frame.to_bytes()
    

if __name__ == "__main__":
  # channel 1
  lgmt_frame_data = b'\x01\x00\x00\x00\xb9\xf1\xe8\x94\x9bL\x07\x00@\x00\x00\x00\xca\xbc\x17\xdd*j\xea\x96\x99~M\xc9\xe59\x13+\xb6\xde\xdf\x0f\x0c\x15\xf5Y\xb54\xa0\x80\x06\xad\xb5\xfc7\xa9\xa0Z\x96$\xb1\x92\x81\xe2\xc6\xfc\xe8\xcf\x07\xd0\xcf\x042\x02\xf7\xa8\xe2\x8d\xdb&\x0b\xf3"\x1f\xca\x83Nt\xb5/|)V\xe8\xade\xd9\xd7\xa0X\n\xfa\xe4\x87\r9\x06\xf5\xc0\xcc78g\xde\xd1\xaf\xeec\xac\xa1\xe7Y\x03~:T\xb1"\xd9\xaf\x85:\xde\xf4'
  attacker_wrapper = ExpiredSubWrapper(lgmt_frame_data)
  forged_frame= attacker_wrapper._flipped_frame()
  print(forged_frame)
  interface = DecoderIntf("/dev/tty.usbmodem21402")
  # interface.decode(forged_frame)
  # interface.decode(forged_frame)
