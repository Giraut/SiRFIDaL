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

To add or remove rules for automatic typing with a simple GUI panel without
running the program with the -w or -r argouments, press and hold the hotkeys
defined in "edit_scan_hotkeys" in the sirfidal_clients_parameters.py file and
scan a tag to bring up the GUI panel.

This program is a SiRFIDaL client. It requires the SiRFIDaL server to interact
with authenticated RFID / NFC transponders.
"""

### Modules
import re
import os
import sys
import json
import psutil
import secrets
import argparse
import Xlib.display
from tkinter import *
from time import sleep
from Xlib import X, XK
from Xlib.ext import record
from Xlib.protocol import rq
from tkinter import messagebox
from signal import signal, SIGCHLD
from setproctitle import setproctitle
from base64 import b64encode, b64decode
from multiprocessing import Process, Queue
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
edit_scan_hotkeys = set(scc.edit_scan_hotkeys) \
			if "edit_scan_hotkeys" in dir(scc) else None



### Defines
KEYBOARD_EVENT_LISTENER_UPDATE = 0
GUI_ACTION = 1



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



def encrypt(pst, key):
  """Encrypt a plaintext string into an encrypted base64 string
  """

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key = (key.encode("ascii") * 32)[:32]

  # Encrypt the string
  nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time
  es = nonce + AESGCM(key).encrypt(nonce, pst.encode("utf-8"), b"")

  # Return the encrypted text as a base64 string
  return b64encode(es).decode("ascii")



def decrypt(bes, key):
  """Decrypt an encrypted base64 string into a plaintext string
  """

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key = (key.encode("ascii") * 32)[:32]

  try:
    es = b64decode(bes)
    return AESGCM(key).decrypt(es[:12], es[12:], b"").decode("utf-8")
  except:
    return None



def update_defsfile(new_entry, winapp, winclass, winname, auth_uid):
  """Update the definitions file: if new_entry is not None, try to update the
  definitions associated with winapp, winclass and winname with this new entry.
  If it is None, delete the definition.
  Return (retcode, message)
  """

  # Load the existing definitions file if one exists
  if not load_defsfile():
    return (-1, "Error loading the definitions file")

  # Create the contents of the new definitions file
  new_defsfile = []
  defsfile_modified = False
  entry_appended = False

  for d in defsfile:

    # Find a matching window in the definitions file
    if d[0] == winapp and d[1] == winclass and d[2] == winname:

      # Decrypt the encrypted string associated with the window
      s = decrypt(d[3], auth_uid)

      # If the decryption didn't succeed, try the next definition
      if s is None:
        new_defsfile.append(d)
        continue

      # The decryption succeeded: change the string definition if we have a new
      # entry or forget it if we don't
      if not defsfile_modified:

        if new_entry is not None:
          new_defsfile.append([winapp, winclass, winname,
				encrypt(new_entry, auth_uid)])

        defsfile_modified = True
        retmsg = "{} existing entry for this window".format("Updated" \
			if new_entry is not None else "Removed")
        retcode = 0

    else:
      new_defsfile.append(d)

  # If we haven't updated or deleted a definition, we should add one
  if not defsfile_modified:

    if new_entry is not None:

      new_defsfile.append([winapp, winclass, winname,
				encrypt(new_entry, auth_uid)])
      defsfile_modified = True
      retmsg = "Created entry for this window"
      retcode = 0

    else:
      retmsg = "No entry found for this window"
      retcode = -1

  # Save the new definition file
  if defsfile_modified and not write_defsfile(new_defsfile):

    retmsg = "Error writing the definitions file"
    retcode = -1

  return (retcode, retmsg)



def keyboard_event_listener(main_in_q):
  """Keyboard event listener
  """

  setproctitle("sirfidal_autotype_keyboard_event_listener")

  # Create a dictionary of keysyms to XK_* key names
  keysym_to_keyname = {}
  for xk in dir(XK):
    if xk[:3] == "XK_":
      keysym_to_keyname[getattr(XK, xk)] = xk[3:]

  # Get the display
  display = Xlib.display.Display()

  # Event handler proper
  def event_handler(reply):
    data = reply.data
    while data:
      event, data = rq.EventField(None).parse_binary_value(
					data, display.display, None, None)
      if event.type in (X.KeyPress, X.KeyRelease):
        keysym = display.keycode_to_keysym(event.detail, 0)
        keyname = keysym_to_keyname.get(keysym)
        main_in_q.put((KEYBOARD_EVENT_LISTENER_UPDATE,
				(keyname if keyname is not None else keysym,
				event.type == X.KeyPress)))

  # Create a recoding context
  ctx = display.record_create_context(0, [record.AllClients], [{
					"core_requests": (0, 0),
					"core_replies": (0, 0),
					"ext_requests": (0, 0, 0, 0),
					"ext_replies": (0, 0, 0, 0),
					"delivered_events": (0, 0),
					"device_events": (X.KeyReleaseMask,
							X.ButtonReleaseMask),
					"errors": (0, 0),
					"client_started": False,
					"client_died": False}])

  # Enable the recording context (from which we won't return)
  display.record_enable_context(ctx, lambda reply: event_handler(reply))



def gui_panel(main_in_q, auth_uid, winapp, winclass, winname):
  """Display a simple GUI panel to let the user associate a string with a UID
  and a particular window, or disassociate a string from a window
  """

  setproctitle("sirfidal_autotype_gui_panel")

  # Button callbacks
  def string_set_return_callback(event):
    new_entry = string_entry.get()
    if new_entry:
      main_in_q.put((GUI_ACTION, (new_entry + "\r", winapp, winclass,
					winname, auth_uid)))

  def string_set_button_callback():
    new_entry = string_entry.get()
    if new_entry:
      main_in_q.put((GUI_ACTION, (new_entry + "\r", winapp, winclass,
					winname, auth_uid)))

  def string_remove_button_callback():
    main_in_q.put((GUI_ACTION, (None, winapp, winclass, winname, auth_uid)))

  def cancel_button_callback():
    root.destroy()

  # Create the root window
  root = Tk()

  # Create the panel
  root.title("SiRFIDaL autotype edit")

  main_frame = Frame(root, padx = 4, pady = 4)
  main_frame.grid(column = 0, row = 0)

  wininfo_frame = LabelFrame(main_frame, text = "Window information",
				relief = RIDGE, bd = 4, padx = 4, pady = 4)
  wininfo_frame.grid(column = 0, row = 0, sticky = NS)

  wininfo_frame_winapp_title = Label(wininfo_frame, text = "Application:")
  wininfo_frame_winapp_title.grid(column = 0, row = 0, sticky = E)

  wininfo_frame_winapp_txt = Label(wininfo_frame, text = winapp)
  wininfo_frame_winapp_txt.grid(column = 1, row = 0, sticky = W)

  wininfo_frame_winclass_title = Label(wininfo_frame, text = "Class:")
  wininfo_frame_winclass_title.grid(column = 0, row = 1, sticky = E)

  wininfo_frame_winclass_txt = Label(wininfo_frame, text = winclass)
  wininfo_frame_winclass_txt.grid(column = 1, row = 1, sticky = W)

  wininfo_frame_winname_title = Label(wininfo_frame, text = "Title:")
  wininfo_frame_winname_title.grid(column = 0, row = 2, sticky = E)

  wininfo_frame_winname_txt = Label(wininfo_frame, text = winname)
  wininfo_frame_winname_txt.grid(column = 1, row = 2, sticky = W)

  string_frame = LabelFrame(main_frame, text = "UID association",
				relief = RIDGE, bd = 4, padx = 4, pady = 4)
  string_frame.grid(column = 1, row = 0, sticky = NS)

  string_entry = Entry(string_frame, width = 25)
  string_entry.bind("<Return>", string_set_return_callback)
  string_entry.grid(column = 1, row = 0, sticky = W)

  string_set_button = Button(string_frame, text = "Set string to type:",
				command = string_set_button_callback)
  string_set_button.grid(column = 0, row = 0, sticky = NSEW)

  string_remove_button = Button(string_frame, text = "Remove string",
				command = string_remove_button_callback)
  string_remove_button.grid(column = 0, row = 1, sticky = NSEW)

  cancel_button = Button(string_frame, text = "Cancel",
				command = cancel_button_callback)
  cancel_button.grid(column = 1, row = 1, sticky = E)

  # Ensure our window is on top and try to force the focus on the string entry
  root.attributes('-topmost', True)
  root.focus_force()
  string_entry.focus_force()
  root.update()

  root.mainloop()



def message_popup(is_error, message):
  """Display a message popup - either a info popup or an error popup
  """

  # Create the root window
  root = Tk()

  # Withdraw the root window
  root.withdraw()

  # Display the appropriate popup
  if is_error:
    messagebox.showerror("Error", message)
  else:
    messagebox.showinfo("", message)

  # Destroy the root window
  root.destroy()



### Main routine
def main():
  """Main routine
  """

  global definitions_file

  setproctitle("sirfidal_autotype")

  # SIGCHLD handler to reap defunct GUI panel processes
  guiproc = [None]
  def sigchld_handler(sig, fname):
    os.wait()
    guiproc[0] = None

  # Get the PID of our parent process, to detect if it changes later on
  ppid = psutil.Process().parent()

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
  d = os.environ.get("DISPLAY")
  proc_mutex = "autotype{}".format(d if d else "")

  display = Xlib.display.Display()

  # Full path of the definitions file
  definitions_file = os.path.expanduser(args.defsfile if args.defsfile else \
			scc.default_definitions_file)
  defsfile_locked = False

  # If the definitions file doesn't exist, create it
  if not os.path.isfile(definitions_file) and not write_defsfile([]):
    print("Error creating the definitions file")
    return -1

  # Create a queue for the keyboard event listener to send events back to the
  # main process
  main_in_q = Queue()

  # Start the keyboard event listener if we have defined hotkeys and we haven't
  # been asked to manipulate the definitions file or show window information
  kbdproc = None
  if edit_scan_hotkeys is not None and not args.showwininfo and \
	args.writedefstring is None and not args.removedefstring:
    kbdproc = Process(target = keyboard_event_listener, args = (main_in_q,))
    kbdproc.start()
    keys_pressed = set()

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
        except:
          pass
        defsfile_locked = False
      release_defsfile_lock = False

    # Only bother getting messages from other processes and checking if the GUI
    # panel is running if we have defined hotkeys
    if edit_scan_hotkeys is not None:

      # Get messages from other processes
      while not main_in_q.empty():

        msg = main_in_q.get()

        # Did we get a message from the keyboard event listener?
        if msg[0] == KEYBOARD_EVENT_LISTENER_UPDATE:

          # Read captured keys
          key, state = msg[1]

          # Update the set of keys currently depressed
          if state:
            keys_pressed.add(key)
          else:
            keys_pressed.discard(key)

        # Did we get an action request from the GUI panel (only accept it if
        # the GUI panel is running)?
        elif msg[0] == GUI_ACTION and guiproc[0] is not None:

          new_entry, winapp, winclass, winname, auth_uid = msg[1]

          # Lock the definitions file
          try:
            if sc.mutex_acquire(definitions_file, 1) == scc.OK:
              defsfile_locked = True
            else:
              defsfile_locked = False
          except:
            defsfile_locked = False

          if defsfile_locked == False:
            retcode = -1
            retmsg = "Error securing exclusive access to the definitions file"

          # Kill the gui panel
          if guiproc[0] is not None:
            guiproc[0].kill()

          # Update the definitions file according to what the GUI panel
          # instructed us to do
          if defsfile_locked:
            retcode, retmsg = update_defsfile(new_entry, winapp, winclass,
						winname, auth_uid)
            release_defsfile_lock = True

          # Display an information or error popup
          Process(target = message_popup, args = (retcode != 0, retmsg)).start()

      # If the GUI panel is running, don't do anything else until it dies
      if guiproc[0] is not None:
        sleep(.2)
        continue

    # If our parent process has changed, the session that initially
    # started us has probably terminated, in which case so should we
    if psutil.Process().parent() != ppid:
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
        except:
          defsfile_locked = False

        if defsfile_locked == False:
          print("Error securing exclusive access to the definitions file")
          return -1

      else:

        # Acquire the process mutex. Abort if we can't to avoid running
        # multiple times in the same session
        if sc.mutex_acquire(proc_mutex, 0) == scc.EXISTS:

          print("Error: process already running for this session")

          if kbdproc is not None:
            kbdproc.kill()

          if guiproc[0] is not None:
            guiproc[0].kill()

          return -1

      uids_set = None

    # Get the user's authentication status
    try:
      _, uids = sc.waitauth(wait = 0 if uids_set is None else 1)

    except KeyboardInterrupt:
      return 0

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

        new_entry = (args.writedefstring + ("" if args.nocr else "\r")) \
			if args.writedefstring is not None else None
        retcode, retmsg = update_defsfile(new_entry, wmclass[1],
						wmclass[0], wmname, auth_uid)
        print(retmsg)

        # Sleep a bit before returning and unlocking the definitions file to
        # give another process waiting on a successful authentication to
        # autotype something a chance to choke on the mutex, so it won't
        # immediately autotype the new string for this window
        sleep(1)

        return retcode

      # If the UID was scanned with the right combination of hotkeys depressed,
      # the user wants to add or remove an entry in the definitions file using
      # the GUI
      elif edit_scan_hotkeys is not None and keys_pressed == edit_scan_hotkeys:

        # Spawn a GUI panel
        guiproc[0] = Process(target = gui_panel, args = (main_in_q, auth_uid,
				wmclass[1], wmclass[0], wmname))
        guiproc[0].start()
        signal(SIGCHLD, sigchld_handler)

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
        except:
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
