"""
  @author: Gavin Zhong
  @date: 2025 03/19
  @affiliation: JHU MSSI
  @license: MIT
"""
from pathlib import Path
from dataclasses import dataclass
import struct
import argparse

@dataclass
class Subscription:
  # 4 bytes
  channel: int
  # 48 bytes
  encrypted_data: bytes
  # 16 bytes
  IV: bytes
  
  struct_format = '<I48s16s'
    
  def to_bytes(self) -> bytes:
    return struct.pack(self.struct_format, self.channel, self.encrypted_data, self.IV)
  
  @classmethod
  def from_bytes(cls, data: bytes) -> 'Subscription':
    channel, encrypted_data, IV = struct.unpack(cls.struct_format, data)
    return cls(channel, encrypted_data, IV)
  
class PiratedSubWrapper:
  def __init__(self, sub_path: Path, pirated_decoder_id: int, falsified_decoder_id: int, start_timestamp: int):
    """ 
      @param sub_path: Path to the pirated subscription file
      @param decoder_id: Decoder ID of the pirated subscription which we 
        want to tamper with
      @param falsified_decoder_id: Decoder ID to which we want to falsify
      @param start_timestamp: Start timestamp of the pirated subscription
      @param end_timestamp: End timestamp of the pirated subscription
    """
    self.sub = self._sub_wrapper(sub_path)
    self._falsify_decoder_id(pirated_decoder_id, falsified_decoder_id, start_timestamp)
    self._save_subscription(sub_path)
    
  def _save_subscription(self, sub_path: Path) -> None:
    with open(sub_path.with_name(sub_path.name + ".falsified"), "wb") as f:
      f.write(self.sub.to_bytes())
  
  def _sub_wrapper(self, sub_path: Path) -> Subscription:
    """ Wrap subscription file into a Subscription object """
    def __load_subscription(sub_path: Path) -> bytes:
      with open(sub_path, "rb") as f:
        return f.read()
    return Subscription.from_bytes(__load_subscription(sub_path))

  def _un_interweave(self, data: bytes) -> bytes:
    ret = bytearray()
    for i in range(len(data) // 2):
      ret.append(data[i * 2])
    return bytes(ret)
  
  def _interweave(self, data: bytes, weaved_data: bytes) -> bytes:
    ret = bytearray()
    for i in range(len(data)):
      ret.append(data[i])
      ret.append(weaved_data[i * 2 + 1])
    return bytes(ret)

  def _falsify_decoder_id(self, pirated_decoder_id: int, falsified_decoder_id: int, start_timestamp: int) -> bytes:
    """ The first encrypted 16-byte block is 
    ENC(8-byte interweaved(4-byte decoder_id, 4-byte random checksum bytes)
    + 8-byte interweaved(first 4-byte start_timestamp, 4-byte random checksum bytes))
    
    The second encrypted 16-byte block is
    ENC(8-byte interweaved(second 4-byte start_timestamp, 4-byte random checksum bytes)
    + 8-byte interweaved(first 4-byte end_timestamp, 4-byte random checksum bytes))
    
    The third encrypted 16-byte block is
    ENC(8-byte interweaved(second 4-byte end_timestamp, 4-byte random checksum bytes)
    + 8-byte \x00)
    
    That's all the AES-CBC encrypted blocks.
    
    * Given the fact:
      * plaintext is derived by XOR(IV, cur_decrypted_cipher_block) at the first block
      * and XOR(prev_ciphertext_block, cur_decrypted_cipher_block) at the rest of blocks
      
    * We have the access to `IV` and `clear-text` we care about
    * So we can falsify corresponding block message as we want
    * by flipping the bits of `IV` or `prev_ciphertext_blocks`
    
    * 
    https://alicegg.tech/assets/2019-06-23-aes-cbc/bit_flipping.jpg
    """
    IV = self._un_interweave(self.sub.IV)
    unweaved_cleartext = struct.pack("<IQ", pirated_decoder_id, start_timestamp)[:8]
    # known_bytes_first_decrypted_block = IV ^ cleartext
    unweaved_first_decrypted_block = bytes(x ^ y for x, y in zip(IV, unweaved_cleartext))
    
    unweaved_cleartext = struct.pack("<IQ", falsified_decoder_id, start_timestamp)[:8]
    unweaved_IV = bytes(x ^ y for x, y in zip(unweaved_first_decrypted_block, unweaved_cleartext))
    weaved_IV = self._interweave(unweaved_IV, self.sub.IV)
    
    # Update exploitation IV
    self.sub.IV = weaved_IV
    
if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--pirated_decoder_id", type=int, default=0xaf1eabd7, help="Decoder ID of the pirated subscription which we want to tamper with")
  parser.add_argument("--falsified_decoder_id", type=int, default=0x1b664ce9, help="Decoder ID to which we want to falsify")
  parser.add_argument("--start_timestamp", type=int, default=1909166656876389, help="Start timestamp of the pirated subscription")
  parser.add_argument("--subscription_file", type=Path, default="/Users/jiachengzhong/project/jhu-research/ectf/attack-phase/UCI_package/pirated.sub", help="Subscription output")
  args = parser.parse_args()
  
  PiratedSubWrapper(args.subscription_file, args.pirated_decoder_id, args.falsified_decoder_id, args.start_timestamp)
    
    

    