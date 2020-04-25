#!/usr/bin/python3
"""Utility to show UIDs read by the SiRFIDaL server as they are being read.

THIS SCRIPT MUST BE RUN AS ROOT!

Without arguments, the program prompts the user and displays UIDs indefinitely,
one per line, until the user hits CTRL-C. However, if -w <delay> is passed,
the program will read a single UID then return. If the delay is positive, the
program waits for a single UID for that amount of time. If it's zero or
negative, it waits forever.

With the -q argument, the program does not prompt the user, but simply displays
the UIDs.

It is also possible to modify the output format with the -p / --prefix and
-s / --suffix arguments.

Sample use cases with the optional arguments:

- Pipe UIDs to another program, all on one line, separated by spaces:

    sirfidal_getuids.py -q -s ' ' | some_program

- Collect UIDs into a text file, with "UID=" before the value, and a semicolon
  after the value, one per line:

    sirfidal_getuids.py -q -p UID= -s $';\n' > some_file.txt

- Wait for a UID for 5 seconds, then use that UID as a key to open an encrypted
  hard disk with LUKS:

    sirfidal_getuids.py -q -s '' -w 5 | cryptsetup -d- luksOpen /dev/sda encdev

This program is a SiRFIDaL client. It requires the SiRFIDaL server to read the
UIDs of RFID / NFC transponders.
"""

### Parameters
socket_path="/tmp/sirfidal_server.socket"



### Modules
import re
import sys
import argparse
from time import sleep
from select import select
from datetime import datetime
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_PASSCRED



### Main routine
def main():
  """Main routine
  """

  # Read the command line arguments
  argparser=argparse.ArgumentParser()
  argparser.add_argument(
	  "-w", "--waitone",
	  type=float,
	  dest="timeout",
	  help="Read only one UID then return, waiting no longer than the " \
                "the specified time (0 to wait indefinitely)",
          required=False
	)
  argparser.add_argument(
	  "-q", "--quiet",
	  action="store_true",
	  help="No prompt or error report on stdout",
          required=False
	)
  argparser.add_argument(
	  "-p", "--prefix",
	  type=str,
	  help="UIDs output prefix (default: none)",
	  default="",
          required=False
	)
  argparser.add_argument(
	  "-s", "--suffix",
	  type=str,
	  help="UIDs output suffix (default: newline)",
	  default="\n",
          required=False
	)
  args=argparser.parse_args()
  do_waitone=args.timeout != None
  waitonewait=args.timeout if do_waitone else -1

  uids_list=[]
  sock=None

  waitone_stop_tstamp=datetime.now().timestamp() + waitonewait

  while not do_waitone or waitonewait<=0 or \
	 datetime.now().timestamp() < waitone_stop_tstamp:

    if not sock:

      # Open a socket to the auth server
      try:
        sock=socket(AF_UNIX, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        sock.connect(socket_path)
        if do_waitone and waitonewait>0:
          sock.settimeout(waitonewait)
      except:
        if sock:
          sock.close()
        sock=None
        sleep(.2)
        continue

      # Send the request to the server
      try:
        sock.sendall("WATCHUIDS\n".encode("ascii"))
      except:
        sock.close()
        sock=None
        sleep(.2)
        continue
 
      crecvbuf=""

    clines=[]

    # Wait for data from the socket
    try:
      if not select([sock], [], [], waitonewait if do_waitone and \
		waitonewait>0 else None)[0]:
        sock.close()
        sock=None
        sleep(.2)
        continue
    except KeyboardInterrupt:
      sock.close()
      return(0)
    except:
      sock.close()
      sock=None
      sleep(.2)
      continue
  
    # Get data from the socket
    try:
      b=sock.recv(256).decode("ascii")
    except KeyboardInterrupt:
      sock.close()
      return(0)
    except:
      sock.close()
      sock=None
      sleep(.2)
      continue

    # If we got nothing, the server has closed its end of the socket.
    if len(b)==0:
      sock.close()
      sock=None
      sleep(.2)
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

      # Denied authorization
      if l=="NOAUTH":

        if not args.quiet:
          print("Not authorized! Are you root?")

        sock.close()
        return(-1)

      # We have an update in the list of active UIDs
      elif(re.match("^UIDS(\s[^\s]+)*$", l)):

        last_uids_list=uids_list
        uids_list=sorted(l.split()[1:])

        # Prompt the user if it was the initial update from the server and
        # the list was empty
        if not uids_list and not last_uids_list and not args.quiet:
          print("Waiting for UID{} - CTRL-C to quit...".format(
		"" if do_waitone else "s"))

        else:

          # Output the new UIDs
          for uid in set(uids_list) - set(last_uids_list):

            sys.stdout.write(args.prefix + uid + args.suffix)
            sys.stdout.flush()

            # If we were asked to read only one UID, exit now
            if do_waitone:
              return(0)



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
