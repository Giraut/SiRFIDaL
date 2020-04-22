#!/usr/bin/python3
"""Program to automatically type strings in application windows upon
authenticating with a RFID or NFC UID. Useful for example to enter your master
password in Mozilla Firefox or Mozilla Thunderbird, which don't integrate with
any third-party keyring manager.

To add a rule for automatic typing, invoke the program with the -w argument,
then focus on the window you want to type the string in, then authenticate
with your RFID or NFC transponder. The windows's unique characteristics and
your custom string will be written in the configuration file.

If you don't want the program to type ENTER at the end of the string, use the
-n argument.

Finally, run the program without any arguments to automatically type the strings
in the windows defined in the configuration file.

This program is a SiRFIDaL client. It requires the SiRFIDaL server to interact
with authenticated RFID / NFC transponders.
"""

# Parameters
default_autotype_definitions_file="~/.sirfidal_autotype_definitions"
socket_path="/tmp/sirfidal_server.socket"



# Modules
import re
import os
import sys
import json
import secrets
import argparse
import Xlib.display
from time import sleep
from psutil import Process
from getpass import getuser
from filelock import FileLock
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_PASSCRED
try:
  from xdo import xdo
  typer="xdo"
except:
  try:
    from pynput.keyboard import Controller
    typer="pynput"
  except:
    typer=None
  pass



### Global variables
autotype_definitions_file=None
defsfile_mtime=None
defsfile=[]
defsfile_lock=None
defsfile_locked=False



# Functions
def load_defsfile():
  """Read and verify the content of the definitions file, if it has been
  modified. Return True if the file didn't need reloading and there was
  no error, False in case of read or format error.
  """

  global defsfile_mtime
  global defsfile

  # Get the file's modification time
  try:
    mt=os.stat(autotype_definitions_file).st_mtime
  except:
    return(False)

  # Check if the file needs reloading
  if not defsfile_mtime:
    defsfile_mtime=mt
  else:
    if mt <= defsfile_mtime:
      return(True)

  # Re-read the file
  try:
    with open(autotype_definitions_file, "r") as f:
      new_defsfile=json.load(f)
  except:
    return(False)

  # Validate the structure of the JSON format
  if not isinstance(new_defsfile, list):
    return(False)

  for entry in new_defsfile:
    if not (
	  isinstance(entry, list) and
          len(entry)==4 and
	  isinstance(entry[0], str) and
	  isinstance(entry[1], str) and
	  isinstance(entry[2], str) and
	  isinstance(entry[3], str)
	):
      return(False)

  # Update the definitions currently in memory
  defsfile_mtime=mt
  defsfile=new_defsfile
  return(True)



def write_defsfile(new_defsfile):
  """Save a new definitions file
  """

  try:
    with open(autotype_definitions_file, "w") as f:
      json.dump(new_defsfile, f, indent=2)
  except:
    return(False)

  return(True)

# Encrypt a plaintext string into an encrypted base64 string
def encrypt(pst, key):

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key=(key.encode("ascii") * 32)[:32]

  # Encrypt the string
  nonce=secrets.token_bytes(12)	# GCM mode needs 12 fresh bytes every time
  es=nonce + AESGCM(key).encrypt(nonce, pst.encode("utf-8"), b"")

  # Return the encrypted text as a base64 string
  return(b64encode(es).decode("ascii"))



# Decrypt an encrypted base64 string into a plaintext string
def decrypt(bes, key):

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key=(key.encode("ascii") * 32)[:32]

  try:
    es=b64decode(bes)
    return(AESGCM(key).decrypt(es[:12], es[12:], b"").decode("utf-8"))
  except:
    return(None)
  


def main():
  """Main routine
  """
  global autotype_definitions_file

  # Get the PID of our parent process, to detect if it changes later on
  ppid=Process().parent()

  # Parse the command line arguments if we have parameters
  argparser=argparse.ArgumentParser()

  argparser.add_argument(
	  "-d", "--defsfile",
	  help="Autotype definitions file (default {})".format(
		default_autotype_definitions_file),
	  type=str,
	  default=default_autotype_definitions_file
	)

  mutexargs=argparser.add_mutually_exclusive_group()

  mutexargs.add_argument(
	  "-s", "--showwininfo",
	  help="Don't send any string, just show the current window's info" \
		"when authenticating",
	  action="store_true",
	)
  mutexargs.add_argument(
	  "-w", "--writedefstring",
	  help="Add or update a string in the definition file for the " \
                "current window",
	  type=str,
	)
  mutexargs.add_argument(
	  "-r", "--removedefstring",
	  help="Remove string in the definition file for the current window",
	  action="store_true",
	)

  argparser.add_argument(
	  "-n", "--nocr",
	  help="Don't add a carriage return at the end of the string",
	  action="store_true",
	)

  args=argparser.parse_args()

  autotype_definitions_file=os.path.expanduser(args.defsfile) \
				if args.defsfile \
				else default_autotype_definitions_file
  defsfile_lock=FileLock(autotype_definitions_file + ".lock")

  # Get the user's name
  user=getuser()

  # If the definitions file doesn't exist, create it
  if not os.path.isfile(autotype_definitions_file) and not write_defsfile([]):
    print("Error creating the definitions file")
    return(-1)

  sock=None
  defsfile_locked=False
  do_release_defsfile_lock=False
  do_return_status=None

  firstauth=True

  # Main loop
  while True:

    # If the definitions file lock is locked, release it if we've been told to,
    # if the socket is closed or if we're about to return
    if (do_release_defsfile_lock or not sock or do_return_status!=None) \
	and defsfile_locked:
      defsfile_lock.release()
      defsfile_locked=False
      do_release_defsfile_lock=False

    # Do return if we've been told to
    if do_return_status!=None:
      return(do_return_status)

    # If our parent process has changed, the session that initially started
    # us up has probably terminated - in which case, we should terminate also
    if Process().parent()!=ppid:
      do_return_status=0
      continue

    if not sock:

      # Open a socket to the auth server
      try:
        sock=socket(AF_UNIX, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        sock.connect(socket_path)
        sock.settimeout(5)	# Don't get stuck on a closed socket
      except:
        if sock:
          sock.close()
        sock=None
        sleep(1)
        continue

      user_authenticated=False
      crecvbuf=""

      # If we're asked to manipulate the definition file, lock it before
      # the user authenticates, so another instance of the program can't
      # trigger an autotype with an old definition before we've had a
      # chance to change the file
      if args.writedefstring!=None or args.removedefstring:
        try:
          defsfile_lock.acquire(timeout=1)
          defsfile_locked=True
        except:
          defsfile_locked=False
          print("Error securing exclusive access to the definitions file")
          print("Maybe delete {} if it's stale?".format(
		autotype_definitions_file + ".lock"))
          do_return_status=-1
          continue

    # Send the request to the server
    try:
      sock.sendall("WAITAUTH {} 1\n".format(user).encode("ascii"))
    except:
      sock.close()
      sock=None
      sleep(1)
      continue

    # Get the user's authentication status
    last_user_authenticated=user_authenticated
    user_authenticated=None

    while user_authenticated==None:

      clines=[]

      if firstauth:

        print("Waiting for UID - CTRL-C to quit...")
        firstauth=False
       
      # Get data from the socket
      try:
        b=sock.recv(256).decode("ascii")
      except KeyboardInterrupt:
        sock.close()
        sock=None
        do_return_status=0
        break
      except:
        sock.close()
        sock=None
        break

      # If we got nothing, the server has closed its end of the socket.
      if len(b)==0:
        sock.close()
        sock=None
        break

      # Read CR- or LF-terminated lines
      for c in b:

        if c=="\n" or c=="\r":
          clines.append(crecvbuf)
          crecvbuf=""

        elif len(crecvbuf)<256 and c.isprintable():
          crecvbuf+=c

      # Process the lines
      for l in clines:

        # Retrieve the user's authentication status from the server's reply
        if l[:6] == "AUTHOK":
          user_authenticated=True
          auth_uid=l[6:].strip()

        elif l == "NOAUTH":
          user_authenticated=False

    if not sock:
      if do_return_status==None:
        sleep(1)
      continue

    # The user has just authenticated
    if not last_user_authenticated and user_authenticated:

      # Check that the server has returned a UID - it should not reply without
      # sending us one, since we requested authentication for ourselves
      if not auth_uid:
        print("Error: the server didn't return a UID")
        continue

      # Get the active window
      try:

        display=Xlib.display.Display()

        window=display.get_input_focus().focus
        wmclass=window.get_wm_class()
        wmname=window.get_wm_name()

        if wmname==None:
          window=window.query_tree().parent
          wmname=window.get_wm_name()
          wmclass=window.get_wm_class()

        if wmname==None or wmclass==None or len(wmclass)<2:
          print("Error getting the window in focus")
          continue

      except:
        print("Error getting the window in focus. Are you running in X?")
        continue

      # Only print the information of the window in focus
      if args.showwininfo:

        print("Window in focus:")
        print("    Application: {}".format(wmclass[1]))
        print("    class:       {}".format(wmclass[0]))
        print("    Title:       {}".format(wmname))

        do_return_status=0
        continue

      # Create an entry, replace an existing entry or delete any entries for
      # this window in the
      # definitions file
      elif args.writedefstring!=None or args.removedefstring:

        # Load the existing definitions file if one exists
        if not load_defsfile():
          print("Error loading the definitions file")
          do_return_status=-1
          continue

        # Create the contents of the new definitions file
        new_defsfile=[]
        defsfile_modified=False
        entry_appended=False

        # New entry in plaintext
        newstr=(args.writedefstring if args.writedefstring!=None else "") + \
		("" if args.nocr else "\r")

        # New entry as an encrypted base64 string
        newstr=encrypt(newstr, auth_uid)

        for d in defsfile:
          
          if d[0]==wmclass[1] and d[1]==wmclass[0] and d[2]==wmname:

            if not defsfile_modified:

              if args.writedefstring!=None:
                new_defsfile.append([wmclass[1], wmclass[0], wmname, newstr])

              defsfile_modified=True
              print("{} existing entry for this window".format(
			"Updated" if args.writedefstring!=None else "Removed"))

          else:
              new_defsfile.append(d)

        if not defsfile_modified:

          if args.writedefstring!=None:

            new_defsfile.append([wmclass[1], wmclass[0], wmname, newstr])
            defsfile_modified=True
            print("Created entry for this window")

          else:
            print("No entry found for this window")

        do_return_status=0

        # Save the new definition file
        if defsfile_modified and not write_defsfile(new_defsfile):

          print("Error writing the definitions file")
          do_return_status=-1

        # Sleep a bit before releasing the lockfile and returning, to give
        # another process waiting on a successful authentication to autotype
        # something a chance to choke on the lock, so it won't immediately
        # autotype the new string
        sleep(1)
        continue

      # "Type" string if we find a definition matching the window currently in
      # focus
      else:

        # Acquire the lock to the definitions file. If we can't, quietly pass
        # our turn
        try:
          defsfile_lock.acquire(timeout=0)
          defsfile_locked=True
        except:
          defsfile_locked=False
          continue

        if not load_defsfile():
          print("Error loading the definitions file")

        else:

          # Find a matching window in the definitions file
          for d in defsfile:

            if d[0]==wmclass[1] and d[1]==wmclass[0] and d[2]==wmname:

              # Decrypt the encrypted string to type
              s=decrypt(d[3], auth_uid)
              if s==None:
                print("Error decrypting the string to type. Are you sure " \
			"it was encoded with this UID?")
                break

              # "Type" the corresponding string
              if typer=="xdo":
                try:
                  xdo().enter_text_window(s)
                except:
                  print("Error typing synthetic keyboard events using xdo")

              elif typer=="pynput":
                try:
                  kbd=Controller()
                  kbd.type(s)
                except:
                  print("Error typing synthetic keyboard events using pynput")

              else:
                print("Error: no usable typer module. Install xdo or pynput")

              break

        do_release_defsfile_lock=True

    # If the server has returned a successful authentication, sleep a bit so we
    # don't run a tight loop as long as the UID is active
    if user_authenticated:
      sleep(0.2)



# Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
