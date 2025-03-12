import json
import argparse
import base64

class FormatConverter:
  """Convert recording.json to the format that is compatible with stress_test.py
  @param input_file: the input recording.json
  @param channel: the channel number of converted recording frames
  @param output_file: the output of stress_test format frames
  """
  def __init__(self, input_file, output_file, channel):
    with open(input_file, "r") as f:
      self.input = json.load(f)
    self.output_file = output_file
    self.channel = channel
    
  def _convert(self, input_objs, channel):
    output = []
    for obj in input_objs:
      output.append([channel, base64.b64encode(bytes.fromhex(obj['encoded'])).decode(), obj['timestamp']])
    return output
  
  def _save_output(self, output):
    with open(self.output_file, "w") as f:
      json.dump(output, f)
  
  def run(self):
    output = self._convert(self.input, self.channel)
    self._save_output(output)
    
if __name__ == "__main__":
  mode = 'prod'
  if mode == "test":
    input_file = '/Users/jiachengzhong/project/jhu-research/ectf/attack-phase/binghamton_package/recording.json'
    output_file = '/Users/jiachengzhong/project/jhu-research/ectf/attack-phase/binghamton_package/recording_stress_format.json'
    channel = 1
    converter = FormatConverter(input_file, output_file, channel)
    converter.run()
  else:
    argparser = argparse.ArgumentParser()
    argparser.add_argument("input_file", type=str, help="the input recording.json")
    argparser.add_argument("output_file", type=str, help="the output of stress_test format frames")
    argparser.add_argument("channel", type=int, help="the channel number of converted recording frames")
    args = argparser.parse_args()
    converter = FormatConverter(args.input_file, args.output_file, args.channel)
    converter.run()
  

    
