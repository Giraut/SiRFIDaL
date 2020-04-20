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

The permissions on the configuration file should be set at 600 if you intend
to have the program type passwords, so that other users can't read the file
with your passwords in it.

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
import argparse
import Xlib.display
from time import sleep
from psutil import Process
from getpass import getuser
from filelock import FileLock
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



def main():
  """Main routine
  """
  global autotype_definitions_file
  global defsfile_lock
  global defsfile_locked

  # Get the PID of our parent process, to detect if it changes later on
  ppid=Process().parent()

  # Parse the command line arguments if we have parameters
  argparser=argparse.ArgumentParser()

  argparser.add_argument(
	  "-d", "--defsfile",
	  help="Autotype definitions file (default {})".format(
		default_autotype_definitions_file),
	  type=str,
	  default=os.path.expanduser(default_autotype_definitions_file)
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

  firstauth=True

  sock=None

  while True:

    # If our parent process has changed, the session that initially started
    # us up has probably terminated - in which case, we should terminate also
    if Process().parent()!=ppid:
      return(0)

    if not sock:

      # Open a socket to the auth server
      try:
        sock=socket(AF_UNIX, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        sock.connect(socket_path)
        sock.settimeout(10)	# Don't get stuck on a closed socket
      except:
        if sock:
          sock.close()
        sock=None
        try:
          sleep(1)
        except:
          return(0)
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
        except:
          print("Error securing exclusive access to the definitions file")
          return(-1)
        defsfile_locked=True

    # Send the request to the server
    try:
      sock.sendall("WAITAUTH {} 1\n".format(user).encode("ascii"))
    except:
      sock.close()
      sock=None
      try:
        sleep(1)
      except:
        return(0)
      continue

    # Get the user's authentication status
    last_user_authenticated=user_authenticated
    user_authenticated=None

    while user_authenticated==None:

      clines=[]

      if firstauth:

        print("Waiting for UIDs - CTRL-C to quit...")
        firstauth=False
       
      # Get data from the socket
      try:
        b=sock.recv(256).decode("ascii")
      except KeyboardInterrupt:
        sock.close()
        return(0)
      except:
        sock.close()
        sock=None
        try:
          sleep(1)
        except:
          return(0)
        break

      # If we got nothing, the server has closed its end of the socket.
      if len(b)==0:
        sock.close()
        sock=None
        try:
          sleep(1)
        except:
          return(0)
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
        if l == "AUTHOK":
          user_authenticated=True

        elif l == "NOAUTH":
          user_authenticated=False

    if not sock:
      continue

    # The user has just authenticated
    if not last_user_authenticated and user_authenticated:

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

        return(0)

      # Create an entry, replace an existing entry or delete any entries for
      # this window in the
      # definitions file
      elif args.writedefstring!=None or args.removedefstring:

        # Load the existing definitions file if one exists
        if not load_defsfile():
          print("Error loading the definitions file")
          return(-1)

        # Create the contents of the new definitions file
        new_defsfile=[]
        defsfile_modified=False
        entry_appended=False

        newstr=(args.writedefstring if args.writedefstring!=None else "") + \
		("" if args.nocr else "\r")

        for d in defsfile:
          
          if d[0]==wmclass[1] and d[1]==wmclass[0] and d[2]==wmname:

            if not defsfile_modified:

              if args.writedefstring!=None:
                new_defsfile.append([wmclass[1], wmclass[0], wmname, newstr])

              defsfile_modified=True
              print("{} existing entry for this window".format(
			"Updated" if args.writedefstring!=None else "Deleted"))

          else:
              new_defsfile.append(d)

        if not defsfile_modified:

          if args.writedefstring!=None:

            new_defsfile.append([wmclass[1], wmclass[0], wmname, newstr])
            defsfile_modified=True
            print("Created entry for this window")

          else:
            print("No entry found for this window")

        retcode=0

        # Save the new definition file
        if defsfile_modified and not write_defsfile(new_defsfile):

          print("Error writing the definitions file")
          retcode=-1

        # Release the lock to the definitions file, but sleep a bit first, in
        # case we ran faster than another instance of the program, to give it
        # a chance to choke on the lock and not send a string rightaway
        sleep(1)
        defsfile_lock.release()
        defsfile_locked=False

        return(retcode)

      # "Type" string if we find a definition matching the window currently in
      # focus
      else:

        # Acquire the lock to the definitions file. If we can't, quietly pass
        # our turn
        try:
          defsfile_lock.acquire(timeout=1)
        except:
          continue

        defsfile_locked=True

        if not load_defsfile():
          print("Error loading the definitions file")

        else:

          # Find a matching window in the definitions file
          for d in defsfile:

            if d[0]==wmclass[1] and d[1]==wmclass[0] and d[2]==wmname:

              # "Type" the corresponding string
              if typer=="xdo":
                try:
                  xdo().enter_text_window(d[3])
                except:
                  print("Error typing synthetic keyboard events using xdo")

              elif typer=="pynput":
                try:
                  kbd=Controller()
                  kbd.type(d[3])
                except:
                  print("Error typing synthetic keyboard events using pynput")

              else:
                print("Error: no usable typer module. Install xdo or pynput")

              break

        # Release the lock to the definitions file
        defsfile_lock.release()
        defsfile_locked=False

    #If the server has returned a successful authentication, sleep a bit so we
    # don't run a tight loop as long as the UID is active
    if user_authenticated:
      sleep(0.2)


# Jump to the main routine
if __name__=="__main__":

  exitcode=main()

  # Release lock to the definitions file if it's been acquired
  if defsfile_locked:
    # We probably got here if there was an error
    defsfile_lock.release()

  sys.exit(exitcode)
