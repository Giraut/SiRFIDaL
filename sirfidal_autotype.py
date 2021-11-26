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

### Modules
import re
import os
import sys
import json
import secrets
import argparse
import Xlib.display
from time import sleep
from psutil import Process
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sirfidal_client_class as scc

try:
  from xdo import xdo
  typer = "xdo"
except:
  try:
    from pynput.keyboard import Controller
    typer = "pynput"
  except:
    typer = None
  pass



### Parameters
scc.load_parameters("sirfidal_autotype")



### Global variables
definitions_file = None
defsfile_mtime = None
defsfile = []
defsfile_locked = False



### Routines
def load_defsfile():
  """Read and verify the content of the definitions file, if it has been
  modified. Return True if the file didn't need reloading and there was
  no error, False in case of read or format error.
  """

  global defsfile_mtime
  global defsfile

  # Get the file's modification time
  try:
    mt = os.stat(definitions_file).st_mtime
  except:
    return False

  # Check if the file needs reloading
  if not defsfile_mtime:
    defsfile_mtime = mt
  else:
    if mt <= defsfile_mtime:
      return True

  # Re-read the file
  try:
    with open(definitions_file, "r") as f:
      new_defsfile = json.load(f)
  except:
    return False

  # Validate the structure of the JSON format
  if not isinstance(new_defsfile, list):
    return False

  for entry in new_defsfile:
    if not (isinstance(entry, list) and \
		len(entry) == 4 and \
		isinstance(entry[0], str) and \
		isinstance(entry[1], str) and \
		isinstance(entry[2], str) and \
		isinstance(entry[3], str)):
      return False

  # Update the definitions currently in memory
  defsfile_mtime = mt
  defsfile = new_defsfile
  return True



def write_defsfile(new_defsfile):
  """Save a new definitions file
  """

  try:
    with open(definitions_file, "w") as f:
      json.dump(new_defsfile, f, indent = 2)
  except:
    return False

  return True

# Encrypt a plaintext string into an encrypted base64 string
def encrypt(pst, key):

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key = (key.encode("ascii") * 32)[:32]

  # Encrypt the string
  nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time
  es = nonce + AESGCM(key).encrypt(nonce, pst.encode("utf-8"), b"")

  # Return the encrypted text as a base64 string
  return b64encode(es).decode("ascii")



# Decrypt an encrypted base64 string into a plaintext string
def decrypt(bes, key):

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key = (key.encode("ascii") * 32)[:32]

  try:
    es = b64decode(bes)
    return AESGCM(key).decrypt(es[:12], es[12:], b"").decode("utf-8")
  except:
    return None



### Main routine
def main():
  """Main routine
  """

  global definitions_file

  # Get the PID of our parent process, to detect if it changes later on
  ppid = Process().parent()

  # Parse the command line arguments if we have parameters
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-d", "--defsfile",
	help = "Autotype definitions file (default {})"
		.format(scc.default_definitions_file),
	type = str,
	default = scc.default_definitions_file)

  mutexargs = argparser.add_mutually_exclusive_group()

  mutexargs.add_argument(
	"-s", "--showwininfo",
	help = "Don't send any string, just show the current window's info " \
		"when authenticating",
	action = "store_true")

  mutexargs.add_argument(
	"-w", "--writedefstring",
	help = "Add or update a string in the definition file for " \
                "the current window",
	type = str)

  mutexargs.add_argument(
	"-r", "--removedefstring",
	help = "Remove string in the definition file for the current window",
	action = "store_true")

  argparser.add_argument(
	"-n", "--nocr",
	help = "Don't add a carriage return at the end of the string",
	action = "store_true")

  args = argparser.parse_args()

  # Name of the mutex to ensure only one process runs per session
  display = os.environ.get("DISPLAY")
  proc_mutex = "autotype{}".format(display if display else "")

  # Full path of the definitions file
  definitions_file = os.path.expanduser(args.defsfile if args.defsfile else \
			scc.default_definitions_file)
  defsfile_locked = False

  # If the definitions file doesn't exist, create it
  if not os.path.isfile(definitions_file) and not write_defsfile([]):
    print("Error creating the definitions file")
    return -1

  uids_set = None

  release_defsfile_lock = False

  sc = None

  # Main loop
  while True:

    # Release the definition file lock if needed
    if release_defsfile_lock:
      if defsfile_locked:
        try:
          sc.mutex_release(definitions_file)
        except Exception as e:
          pass
        defsfile_locked = False
      release_defsfile_lock = False

    # If our parent process has changed, the session that initially
    # started us has probably terminated, in which case so should we
    if Process().parent() != ppid:
      return 0

    # Connect to the server
    if sc is None:
      try:
        sc = scc.sirfidal_client()

      except KeyboardInterrupt:
        return 0

      except:
        sleep(1)	# Wait a bit before reconnecting in case of error
        sc = None
        continue

      # Have we been asked to manipulate the definitions file or show window
      # information?
      if args.showwininfo or args.writedefstring is not None or \
		args.removedefstring:

        # Lock the definitions file before the user authenticates, so another
        # instance of the program can't trigger an autotype while we're busy
        # modifying the definitions file or showing window information
        try:
          if sc.mutex_acquire(definitions_file, 1) == scc.OK:
            defsfile_locked = True
          else:
            defsfile_locked = False
        except Exception as e:
          defsfile_locked = False

        if defsfile_locked == False:
          print("Error securing exclusive access to the definitions file")
          return -1

      else:

        # Acquire the process mutex. Abort if we can't to avoid running
        # multiple times in the same session
        if sc.mutex_acquire(proc_mutex, 0) == scc.EXISTS:
          print("Error: process already running for this session")
          return -1

      uids_set = None

    # Get the user's authentication status
    try:
      _, uids = sc.waitauth(wait = 0 if uids_set is None else 1)

    except KeyboardInterrupt:
      release_defsfile_lock = True
      return 0
      continue

    except:
      try:
        del(sc)
      except:
        pass
      sc = None
      release_defsfile_lock = True
      sleep(1)	# Wait a bit before reconnecting in case of error
      continue

    # If we got the first set of UIDs, prompt the user and initialize
    # the UIDs sets
    if uids_set is None:
      print("Waiting for UIDs - CTRL-C to quit...")
      uids_set = set(uids)

    uids_set_prev = uids_set
    uids_set = set(uids)

    # Do we have new UIDs - meaning either the user has authenticated for the
    # first time, or has authenticated again with one or more new UID(s)?
    new_uids = uids_set - uids_set_prev

    if new_uids:

      # Use the first of the new UIDs
      auth_uid = sorted(new_uids)[0]

      # Get the active window
      try:

        display = Xlib.display.Display()

        window = display.get_input_focus().focus
        wmclass = window.get_wm_class()
        wmname = window.get_wm_name()

        if wmname == None:
          window = window.query_tree().parent
          wmname = window.get_wm_name()
          wmclass = window.get_wm_class()

        if wmname == None or wmclass == None or len(wmclass) < 2:
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

        # Sleep a bit before returning and unlocking the definitions file to
        # give another process waiting on a successful authentication to
        # autotype something a chance to choke on the mutex, so it won't
        # immediately autotype a matching definition for this window
        sleep(1)

        return 0

      # Create an entry, replace an existing entry or delete any entries for
      # this window in the definitions file
      elif args.writedefstring is not None or args.removedefstring:

        # Load the existing definitions file if one exists
        if not load_defsfile():
          print("Error loading the definitions file")
          return -1

        # Create the contents of the new definitions file
        new_defsfile = []
        defsfile_modified = False
        entry_appended = False

        # New entry in plaintext
        newstr = (args.writedefstring if args.writedefstring is not None else \
			"") + ("" if args.nocr else "\r")

        # New entry as an encrypted base64 string
        newstr = encrypt(newstr, auth_uid)

        for d in defsfile:

          # Find a matching window in the definitions file
          if d[0] == wmclass[1] and d[1] == wmclass[0] and d[2] == wmname:

            # Decrypt the encrypted string associated with the window
            s = decrypt(d[3], auth_uid)

            # If the decryption didn't succeed, try the next definition
            if s is None:
              new_defsfile.append(d)
              continue

            if not defsfile_modified:

              if args.writedefstring is not None:
                new_defsfile.append([wmclass[1], wmclass[0], wmname, newstr])

              defsfile_modified = True
              print("{} existing entry for this window".format(
			"Updated" if args.writedefstring is not None else \
			"Removed"))

          else:
              new_defsfile.append(d)

        if not defsfile_modified:

          if args.writedefstring is not None:

            new_defsfile.append([wmclass[1], wmclass[0], wmname, newstr])
            defsfile_modified = True
            print("Created entry for this window")

          else:
            print("No entry found for this window")

        retcode = 0

        # Save the new definition file
        if defsfile_modified and not write_defsfile(new_defsfile):

          print("Error writing the definitions file")
          retcode = -1

        # Sleep a bit before returning and unlocking the definitions file to
        # give another process waiting on a successful authentication to
        # autotype something a chance to choke on the mutex, so it won't
        # immediately autotype the new string for this window
        sleep(1)

        return retcode

      # "Type" string if we find a definition matching the window currently in
      # focus
      else:

        # Acquire the mutex to the definitions file. If we can't, quietly pass
        # our turn
        try:
          if sc.mutex_acquire(definitions_file, 0) == scc.OK:
            defsfile_locked = True
          else:
            defsfile_locked = False
            continue
        except Exception as e:
          defsfile_locked = False
          continue

        if not load_defsfile():
          print("Error loading the definitions file")

        else:

          # Find a matching window in the definitions file
          for d in defsfile:

            if d[0] == wmclass[1] and d[1] == wmclass[0] and d[2] == wmname:

              # Decrypt the encrypted string associated with the window
              s = decrypt(d[3], auth_uid)

              # If the decryption didn't succeed, try the next definition
              if s is None:
                continue

              # "Type" the corresponding string
              if typer == "xdo":
                try:
                  xdo().enter_text_window(s)
                except:
                  print("Error typing synthetic keyboard events using xdo")

              elif typer == "pynput":
                try:
                  kbd = Controller()
                  kbd.type(s)
                except:
                  print("Error typing synthetic keyboard events using pynput")

              else:
                print("Error: no usable typer module. Install xdo or pynput")

              break

        release_defsfile_lock = True

    # If the server has returned a successful authentication but the set of
    # active authenticated UIDs hasn't changed, sleep a bit so we don't run
    # a tight loop as long as the same UIDs are active
    if uids_set and uids_set == uids_set_prev:
      sleep(.2)



### Jump to the main routine
if __name__ == "__main__":
  sys.exit(main())
