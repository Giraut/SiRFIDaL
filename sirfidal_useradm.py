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
uid_read_wait=5 #s
socket_path="/tmp/sirfidal_server.socket"



### Modules
import os
import sys
import pwd
import argparse
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_PASSCRED



### Main routine
def main():
  """Main routine
  """

  # Get the current username
  pw_name=pwd.getpwuid(os.getuid()).pw_name

  # Read the command line arguments
  argparser=argparse.ArgumentParser()
  mutexargs=argparser.add_mutually_exclusive_group(required=True)
  mutexargs.add_argument(
	  "-a", "--adduser",
	  type=str,
          nargs="?",
          const=pw_name,
	  help="Associate a user with a NFC / RFID UID"
	)
  mutexargs.add_argument(
	  "-d", "--deluser",
	  type=str,
          nargs="?",
          const=pw_name,
	  help="Disassociate a user from a NFC / RFID UID"
	)
  mutexargs.add_argument(
	  "-D", "--delalluser",
	  type=str,
          nargs="?",
          const=pw_name,
	  help="Remove all NFC / RFID UID association for a user"
	)
  args=argparser.parse_args()

  # Open a socket to the auth server
  try:
    sock=socket(AF_UNIX, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
    sock.connect(socket_path)

    # Make sure we never get stuck on an idle server
    sock.settimeout(uid_read_wait + 5)
  except:
    print("Error connecting to the server")
    return(-1)

  # Send the request to the server
  try:
    sock.sendall("{cmd} {usr} {wait}\n".format(
	  cmd="ADDUSER" if args.adduser else "DELUSER",
	  usr=args.adduser if args.adduser else args.deluser if args.deluser \
		else args.delalluser,
	  wait="-1" if args.delalluser else uid_read_wait
	).encode("ascii"))
  except:
    print("Error sending the request to the server")
    return(-2)

  # If the action is interactive, tell the user we're waiting for a UID
  if not args.delalluser:
    print("Waiting for UID...")
  
  # Get the reply - one line only
  server_reply=""
  got_server_reply=False

  while not got_server_reply:

    # Get data from the socket
    try:
      b=sock.recv(256).decode("ascii")
    except timeout:
      print("Error: timeout waiting for the server's reply")
      return(-3)
    except:
      print("Error waiting for a server's reply")
      return(-4)

    # If we got nothing, the server has closed its end of the socket.
    if len(b)==0:

      sock.close()
      print("Error: connection to the server unexpectedly closed")
      return(-5)

    # Read one CR- or LF-terminated line
    for c in b:

      if c=="\n" or c=="\r":
        got_server_reply=True
        break

      elif len(server_reply)<256 and c.isprintable():
        server_reply+=c

  sock.close
  
  # Report the result to the user
  unknown_server_reply=True

  if args.adduser:

    if server_reply=="OK":
      unknown_server_reply=False
      print("User {} successfully associated with this UID".format(
		args.adduser))
      return(0)

    elif server_reply=="EXISTS":
      unknown_server_reply=False
      print("Error: user {} already associated with this UID".format(
		args.adduser))
      return(-6)

  elif args.deluser:

    if server_reply=="OK":
      unknown_server_reply=False
      print("User {} successfully disassociated from this UID".format(
		args.deluser))
      return(0)

    elif server_reply=="NONE":
      unknown_server_reply=False
      print("Error: user {} was not associated with this UID".format(
		args.deluser))
      return(-7)

  elif args.delalluser:

    if server_reply=="OK":
      unknown_server_reply=False
      print("All UID associations successfully deleted for user {}".format(
		args.delalluser))
      return(0)

    elif server_reply=="NONE":
      unknown_server_reply=False
      print("Error: user {} was not associated with any UID".format(
		args.delalluser))
      return(-8)

  if server_reply=="NOAUTH":
    unknown_server_reply=False
    print("Error: you are not authorized to perform this operation")
    return(-9)

  elif server_reply=="WRITEERR":
    unknown_server_reply=False
    print("Error: the server cannot write the encrypted UIDs file")
    return(-10)

  elif server_reply=="TIMEOUT":
    unknown_server_reply=False
    print("Error: timeout waiting for UID")
    return(-11)

  if unknown_server_reply:
    print("Unknown server reply: {}".format(server_reply))
    return(-12)



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
