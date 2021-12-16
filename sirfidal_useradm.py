#!/usr/bin/python3
"""Script to add or delete users and their optional secondary authentication
tokens in the SiRFIDaL encrypted UIDs file

This script is a SiRFIDaL client. It forwards requests to add or delete user,
optional secondary authentication token and UID associations to the SiRFIDaL
server.

Only root may add a new user, or add a new user/UID association. However, both
root and the user requesting the association for themselves may add a new
authtok association to an existing user/UID association. Any user/UID/authtok
association may be deleted by root or the user requestion the deletion for
themselves.

No ordinary user may request a new association or a deletion for another user.

If no username is suppose adter -a, -d or -D, the current username is
used.
"""

### Modules
import os
import sys
import pwd
import argparse
from getpass import getpass
import sirfidal_client_class as scc



### Main routine
def main():
  """Main routine
  """

  # Get the current userid and username
  userid = os.getuid()
  pw_name = pwd.getpwuid(userid).pw_name

  # Read the command line arguments
  argparser = argparse.ArgumentParser()

  mutexargs = argparser.add_mutually_exclusive_group(required = True)

  mutexargs.add_argument(
	"-a", "--adduser",
        nargs = "?",
	const = pw_name,
	help = "Associate a user with a NFC / RFID UID, with or without a "
		"secondary authentication token")

  mutexargs.add_argument(
	"-d", "--deluser",
	type = str,
        nargs = "?",
	const = pw_name,
	help = "Delete a user / UID association")

  mutexargs.add_argument(
	"-D", "--delalluser",
	type = str,
        nargs = "?",
	const = pw_name,
	help = "Delete all user / UID associations for a user")

  argparser.add_argument(
	"-w", "--wait",
	type = float,
	help = "Delay (s) to wait for a UID (default {})"
		.format(scc._sirfidal_default_useradm_uid_read_wait),
        default = scc._sirfidal_default_useradm_uid_read_wait,
	required = False)

  args = argparser.parse_args()

  uid_read_wait = max(0, args.wait)

  # If none of the actionable command line arguments contain a valid username,
  # throw an error
  if not args.adduser and not args.deluser and not args.delalluser:
    print("Error: invalid username")
    return -1

  # If the user isn't root and attempts to add an association for another user,
  # block them righaway so they don't waste time entering the authtok
  if args.adduser and userid != 0 and pw_name != args.adduser:
    print("Error: you are not authorized to perform this operation")
    return -1

  # If we add a user/UID/authtok association, prompt for the authtok
  authtok = None
  if args.adduser:

    authtok = getpass("Secondary authentication token (leave blank for none): ")
    if not authtok:
      authtok = None

    elif not authtok.isprintable():
      print("Error: invalid authentication token")
      return -1

  # Send the request to the server and get the reply back
  try:

    with scc.sirfidal_client() as sc:

      if not args.delalluser:
        print("Waiting for UID...")

      if args.adduser:
        reply = sc.adduser(args.adduser, wait = uid_read_wait,
				authtok = authtok)

      elif args.deluser:
        reply = sc.deluser(args.deluser, wait = uid_read_wait)

      elif args.delalluser:
        reply = sc.delalluser(args.delalluser)

  except Exception as e:
    print("Error: {}".format(e))
    return -1

  # Report the result to the user
  if args.adduser:

    if reply == scc.OK:
      print("User {} {} successfully associated with this UID".format(
		args.adduser, ("with no" if not authtok else "and") + \
		" authentication token"))
      return 0

    elif reply == scc.EXISTS:
      print("Error: user {} {} already associated with this UID".format(
		args.adduser, ("without" if not authtok else "with this") + \
		" authentication token"))
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
