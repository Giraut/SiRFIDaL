#!/usr/bin/python3
"""Script to add or delete users in the encrypted UIDs file

This script is a SiRFIDaL client. It forwards requests to associate a user with
a UID and add it to the authorized users, remove a user <-> UID association, or
remove all associations for a user to the SiRFIDaL server.

Only root may assocate / disassociate a user and a UID, or a non-root user for
themselves. If no username is supplied after -a, -d or -D, the current username
is used.
"""

### Parameters
uid_read_wait = 5 #s



### Modules
import os
import sys
import pwd
import argparse
import sirfidal_client_class as scc



### Main routine
def main():
  """Main routine
  """

  # Get the current username
  pw_name=pwd.getpwuid(os.getuid()).pw_name

  # Read the command line arguments
  argparser = argparse.ArgumentParser()

  mutexargs = argparser.add_mutually_exclusive_group(required = True)

  mutexargs.add_argument(
	"-a", "--adduser",
	type = str,
	nargs = "?",
	const = pw_name,
	help = "Associate a user with a NFC / RFID UID")

  mutexargs.add_argument(
	"-d", "--deluser",
	type = str,
        nargs = "?",
	const = pw_name,
	help = "Disassociate a user from a NFC / RFID UID")

  mutexargs.add_argument(
	"-D", "--delalluser",
	type = str,
        nargs = "?",
	const = pw_name,
	help = "Remove all NFC / RFID UID association for a user")

  args=argparser.parse_args()

  # Send the request to the server and get the reply back
  try:

    with scc.sirfidal_client() as sc:

      if not args.adduser and not args.deluser and not args.delalluser:
        print("Error: invalid username")
        return -1

      if not args.delalluser:
        print("Waiting for UID...")

      if args.adduser:
        reply = sc.adduser(args.adduser, wait = uid_read_wait)

      elif args.deluser:
        reply = sc.deluser(args.deluser, wait = uid_read_wait)

      elif args.delalluser:
        reply = sc.delalluser(args.delalluser)

  except Exception as e:
    print("Error: {}".format(e))
    return -1

  # Report the result to the user
  if args.adduser is not None:

    if reply == scc.OK:
      print("User {} successfully associated with this UID".format(
		args.adduser))
      return 0

    elif reply == scc.EXISTS:
      print("Error: user {} already associated with this UID".format(
		args.adduser))
      return -4

  elif args.deluser:

    if reply == scc.OK:
      print("User {} successfully disassociated from this UID".format(
		args.deluser))
      return 0

    elif reply == scc.NONE:
      print("Error: user {} was not associated with this UID".format(
		args.deluser))
      return -5

  elif args.delalluser:

    if reply == scc.OK:
      print("All UID associations successfully deleted for user {}".format(
		args.delalluser))
      return 0

    elif reply == scc.NONE:
      print("Error: user {} was not associated with any UID".format(
		args.delalluser))
      return -5

  if reply == scc.NOAUTH:
    print("Error: you are not authorized to perform this operation")
    return -1

  elif reply == scc.WRITEERR:
    print("Error: the server cannot write the encrypted UIDs file")
    return -2

  elif reply == scc.TIMEOUT:
    print("Error: timeout waiting for UID")
    return -3

  # We should never get here
  print("Unknown server reply: {}".format(reply))
  return -6



### Jump to the main routine
if __name__ == "__main__":
  sys.exit(main())
