#!/usr/bin/python3
"""Script to play a sound when a RFID or NFC transponder is presented to a
reader, and another when it is taken out.

This script is a SiRFIDaL client. It effectively adds audio feedback to readers
that don't have an internal buzzer. This is particularly useful with RFID or
NFC implants, with which is can sometimes be difficult to find the "sweet spot"
on certain readers, due to the reduced range of glass implant transponders.

The script asks the server to get notified when UIDs become active or inactive,
then simply plays the corresponding sound file. The sound files to be played
may be specified with the -u and -d arguments, or encoded permanently in the
parameters below.
"""

### Parameters
default_up_sound_file="sounds/up.wav"
default_down_sound_file="sounds/down.wav"
socket_path="/tmp/sirfidal_server.socket"



### Modules
import re
import os
import sys
import argparse
from time import sleep
from playsound import playsound
from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET, SO_PASSCRED



### Main routine
def main():
  """Main routine
  """

  # Read the command line arguments
  argparser=argparse.ArgumentParser()
  argparser.add_argument(
	  "-u", "--upsoundfile",
	  type=str,
	  help="Sound file to play when a new UID comes up",
          required=False
	)
  argparser.add_argument(
	  "-d", "--downsoundfile",
	  type=str,
	  help="Sound file to play when a UID goes away",
          required=False
	)
  args=argparser.parse_args()

  upsndfile=args.upsoundfile if args.upsoundfile else default_up_sound_file
  downsndfile=args.downsoundfile if args.downsoundfile \
		 else default_down_sound_file

  sock=None

  while True:

    if not sock:

      # Open a socket to the auth server
      try:
        sock=socket(AF_UNIX, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        sock.connect(socket_path)
      except:
        if sock:
          sock.close()
        sock=None
        sleep(1)
        continue

      # Send the request to the server
      try:
        sock.sendall("WATCHNBUIDS\n".encode("ascii"))
      except:
        sock.close()
        sock=None
        sleep(1)
        continue
 
      crecvbuf=""

    clines=[]

    # Get data from the socket
    try:
      b=sock.recv(256).decode("ascii")
    except:
      sock.close()
      sock=None
      sleep(1)
      continue

    # If we got nothing, the server has closed its end of the socket.
    if len(b)==0:
      sock.close()
      sock=None
      sleep(1)
      continue

    # Read CR- or LF-terminated lines
    for c in b:

      if c=="\n" or c=="\r":
        clines.append(crecvbuf)
        crecvbuf=""

      elif len(crecvbuf)<256 and c.isprintable():
        crecvbuf+=c

    # Process the lines
    for l in clines:

      # Only care about active UIDs status updates
      m=re.findall("^NBUIDS\s([0-9]+)\s([-+]?[0-9]+)$", l)
      if m:

        # Play the "up" sound file if the number of active UIDs has
        # increased
        chg=float(m[0][1])

        if chg > 0:
          try:
            playsound(upsndfile)
          except:
            print("Error: cannot play {} sound file".format(upsndfile))

        # Play the "down" sound file if the number of active UIDs has
        # decreased
        elif chg < 0:
          try:
            playsound(downsndfile)
          except:
            print("Error: cannot play {} sound file".format(downsndfile))



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
