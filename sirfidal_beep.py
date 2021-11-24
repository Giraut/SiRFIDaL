#!/usr/bin/python3
"""Script to play a WAV sound file when a RFID or NFC transponder is presented
to a reader, and another when it is taken out.

This script is a SiRFIDaL client. It effectively adds audio feedback to readers
that don't have an internal buzzer. This is particularly useful with RFID or
NFC implants, with which is can sometimes be difficult to find the "sweet spot"
on certain readers, due to the reduced range of glass implant transponders.

The script asks the server to get notified when UIDs become active or inactive,
then simply plays the corresponding sound file.

The sound files to be played may be specified with the -u and -d arguments, or
encoded permanently in the parameters below.

if -u or -d is set to '-' or '', no sound is played.

Note: if you run this script in a Pulseaudio environment and it seems to work
      fine when running in a console but not when running as a systemd service,
      try setting force_restart_pulseaudio to True below
"""

### Modules
import os
import sys
import argparse
from time import sleep
import sirfidal_client_class as scc



### Parameters
scc.load_parameters("sirfidal_beep")



### Extra modules
if scc.use_external_player or scc.force_restart_pulseaudio:
  from subprocess import Popen, DEVNULL
if not scc.use_external_player:
  import wave
  from pyaudio import PyAudio



### Routines
def play_wav_file(fpath):
  """Play a WAV file, either directly using the pyaudio module or using an
  external utility. If required, start a Pulseaudio daemon before playing the
  WAV file: if the Pulseaudio daemon isn't already running, this will start it,
  which is useful if the script isn't run as the currently logged in user. If
  the Pulseaudio daemon is already running, ignore the resulting error message
  and play the WAV file anyway.
  """

  # If required, unconditionally respawn a Pulseaudio daemon before playing
  # the WAV file
  if scc.force_restart_pulseaudio:
    Popen([scc.pulseaudio_command, "-D"], stdin = DEVNULL, stdout = DEVNULL,
					stderr = DEVNULL).wait()

  # Use an external player
  if scc.use_external_player:
    retcode = Popen(scc.external_player_command.format(sndfile = fpath).split(),
		stdin = DEVNULL, stdout = DEVNULL, stderr = DEVNULL).wait()
    if retcode != 0:
      raise RuntimeError("{} returned {}".format(
			scc.external_player_command.format(sndfile = fpath),
			retcode))

  # Use pyaudio
  else:

    # Open the WAV file
    f = wave.open(fpath, "rb")

    # Redirect stderr to /dev/null to hide useless PortAudio messages
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_stderr = os.dup(2)
    sys.stderr.flush()
    os.dup2(devnull, 2)
    os.close(devnull)

    try:
      p = PyAudio()
    except:
      # Restore stderr
      os.dup2(old_stderr, 2)
      os.close(old_stderr)
      raise

    # Restore stderr
    os.dup2(old_stderr, 2)
    os.close(old_stderr)

    # Open the stream
    stream = p.open(format = p.get_format_from_width(f.getsampwidth()),
			channels = f.getnchannels(), rate = f.getframerate(),
			output = True)

    # Send the WAV file to the stream in chunks
    data = f.readframes(1024)
    while data:
      stream.write(data)
      data = f.readframes(1024)

    # Wait a bit to make sure the playback is really over before closing
    # the stream
    sleep(.2)

    stream.stop_stream()
    stream.close()

    p.terminate()



### Main routine
def main():
  """Main routine
  """

  # Read the command line arguments
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-u", "--upsoundfile",
	type = str,
	help = "WAV sound file to play when a new UID comes up (- to disable)",
	required = False)

  argparser.add_argument(
	"-d", "--downsoundfile",
	type = str,
	help = "WAV sound file to play when a UID goes away (- to disable)",
	required = False)

  args = argparser.parse_args()

  upsndfile = args.upsoundfile if args.upsoundfile else \
				scc.default_up_sound_file
  downsndfile = args.downsoundfile if args.downsoundfile else \
				scc.default_down_sound_file

  while True:

    try:

      # Connect to the server
      with scc.sirfidal_client() as sc:

        # Watch the number of active UIDs
        for _, chg in sc.watchnbuids():

          # Play the "up" sound file if the number of active UIDs has
          # increased
          if chg > 0 and upsndfile and upsndfile != "-":
            try:
              play_wav_file(upsndfile)
            except Exception as e:
              print("Error: cannot play {} sound file: {}"
			.format(upsndfile, e))

          # Play the "down" sound file if the number of active UIDs has
          # decreased
          elif chg < 0 and downsndfile and downsndfile != "-":
            try:
              play_wav_file(downsndfile)
            except Exception as e:
              print("Error: cannot play {} sound file: {}"
			.format(downsndfile, e))

    except KeyboardInterrupt:
      return 0

    except:
      sleep(1)	# Wait a bit before reconnecting in case of error



### Jump to the main routine
if __name__ == "__main__":
  sys.exit(main())
