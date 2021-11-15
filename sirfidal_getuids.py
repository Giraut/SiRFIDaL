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

### Modules
import re
import sys
import argparse
from time import time, sleep
import sirfidal_client_class as scc



### Main routine
def main():
  """Main routine
  """

  # Read the command line arguments
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-w", "--waitone",
	type = float,
	dest = "timeout",
	help = "Read only one UID then return, waiting no longer than the " \
		"the specified time (0 to wait indefinitely)",
	required = False)

  argparser.add_argument(
	"-q", "--quiet",
	action = "store_true",
	help = "No prompt or error report on stdout",
	required = False)

  argparser.add_argument(
	"-p", "--prefix",
	type = str,
	help = "UIDs output prefix (default: none)",
	default = "",
	required = False)

  argparser.add_argument(
	"-s", "--suffix",
	type = str,
	help = "UIDs output suffix (default: newline)",
	default = "\n",
	required = False)

  args = argparser.parse_args()

  waitonewait = args.timeout
  if waitonewait is not None:
    if waitonewait < 0:
      print("Error: invalid wait time.")
      return -1
    endwait = time() + waitonewait

  uids_list = None

  while waitonewait is None or time() < endwait:

    try:

      # Connect to the server
      with scc.sirfidal_client() as sc:

        # Watch UIDs
        for r, uids in sc.watchuids(timeout = waitonewait):

          # The server informs us we're not authorized to watch UIDs
          if r == scc.NOAUTH:
            if not args.quiet:
              print("Not authorized! Are you root?")
            return -1

          # If we got the initial UIDs update, prompt the user and initialize
          # the UIDs lists
          if uids_list is None:
            if not args.quiet:
              print("Waiting for UID{} - CTRL-C to quit...".format(
				"" if waitonewait is not None else "s"))
            uids_list = uids

          uids_list_prev = uids_list
          uids_list = uids

          # Output the new UIDs
          for uid in set(uids_list) - set(uids_list_prev):

            sys.stdout.write(args.prefix + uid + args.suffix)
            sys.stdout.flush()

            # If we were asked to read only one UID, exit now
            if waitonewait is not None:
              return 0

    except KeyboardInterrupt:
      return 0

    except:
      uids_list = None
      sleep(.2)	# Wait a bit before reconnecting in case of error or timeout



### Jump to the main routine
if __name__ == "__main__":
  sys.exit(main())
