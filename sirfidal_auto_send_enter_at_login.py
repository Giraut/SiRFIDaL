#!/usr/bin/python3
"""Utility to automatically send ENTER to a virtual console when SiRFIDaL reads
a RFID or NFC UID and no user session is running - i.e. when a text or
graphical login screen is running on the virtual console.

This is useful to dismiss the regular keyboard password entry and immediately
move on to the RFID authentication, if both are used in the PAM configuration.

Example: if the first authentication is pam_unix and the second authentication
         is sirfidal_pam, without this utility, the user must enter or choose
         their username, then press ENTER to enter a blank password, then
         present their RFID or NFC tag within the sirfidal_pam delay - or have
         presented it before typing the blank password. With this utility, the
         user simply enters or chooses their username, presents their RFID
         or NFC tag, and the utility types the blank password automatically,
         with sirfidal_pam getting the UID immediately afterward.

This script calls loginctl to determine the active session (or lack thereof)
on the current virtual console. loginctl is part of systemd. In other words,
this script will not work on systemd-less distros.

THIS SCRIPT MUST BE RUN AS ROOT!
"""

### Modules
import re
import os
import psutil
from time import sleep
from evdev import UInput, ecodes
from subprocess import Popen, PIPE
import sirfidal_client_class as scc



### Routines
def active_vc():
  """Return the name of the current virtual console or None in case of error
  """

  try:
    with open("/sys/class/tty/tty0/active", "rb", buffering = 0) as f:
      active_vc = f.readline().decode("utf-8").strip()
  except:
    active_vc = None

  return active_vc



def get_session_class(vc):
  """Use loginctl to iterate over the list of currently-running sessions and
  return the class of any session running on the virtual console vc, "" if no
  session is found running on that virtual console, or None in case of error
  """

  if vc is None:
    return None

  # Get the list of sessions
  try:
    p = Popen(["loginctl", "list-sessions"], stdout = PIPE)
    loginctl_stdout = p.communicate()[0].decode("utf-8")
    if p.returncode:
      return None

  except:
    return None
    pass

  sessionids = []
  for l in loginctl_stdout.split("\n"):
    m = re.findall("^\s*(\S+)\s+([0-9]+)\s+([!-,\.0-9;A-~]{1,32})\s+.*$", l)
    if m:
      sessionids.append(m[0][0])

  # For each session, get the associated virtual console and class. If the
  # virtual console matches, return the class
  for sessionid in sessionids:

    # Get the session information
    try:
      p = Popen(["loginctl", "show-session", sessionid], stdout = PIPE)
      loginctl_stdout = p.communicate()[0].decode("utf-8")
      if p.returncode:
        return None

    except:
      return None
      pass

    # Extract the virtual console and class. Skip if the virtual console
    # doesn't match. Return the class if it does
    session_vtnr = None
    session_class = None
    for l in loginctl_stdout.split("\n"):
      m = re.findall("^(VTNr|Class)=([\S+]+)$", l)
      if m:
        if m[0][0] == "VTNr":
          session_vtnr = "tty{}".format(m[0][1])
        else:
          session_class = m[0][1]
        if session_vtnr is not None:
          if session_vtnr != vc:
            break
          elif session_class is not None:
            return session_class

  # We didn't find a session with a matching virtual console number
  return ""



### Main routine
def main():
  """Main routine
  """

  uids_list = None

  while True:

    try:

      # Connect to the server
      with scc.sirfidal_client() as sc:

        # Watch UIDs
        for r, uids in sc.watchuids(timeout = None):

          # The server informs us we're not authorized to watch UIDs
          if r == scc.NOAUTH:
            print("Not authorized! Are you root?")
            return -1

          # If we got the initial UIDs update, initialize the UIDs lists
          if uids_list is None:
            uids_list = uids

          uids_list_prev = uids_list
          uids_list = uids

          # Do we have new UIDs?
          if set(uids_list) - set(uids_list_prev):

            # Find out the active virtual console
            vc = active_vc()
            if not vc:
              print("Error determining the active virtual console")
              continue

            # If no session is running on the active virtual console, or a
            # greeter session is running, send the keystroke sequence for
            # ENTER to the console
            if get_session_class(vc) in ("", "greeter"):

              try:
                ui = UInput()
              except:
                print("UInput open error: are you root?")
                continue

              try:
                ui.write(ecodes.EV_KEY, ecodes.KEY_ENTER, 1)
                ui.syn()
                sleep(.1)   # Pause needed for gdm
                ui.write(ecodes.EV_KEY, ecodes.KEY_ENTER, 0)
                ui.syn()
                sleep(.1)   # Pause needed for gdm
                print("ENTER sent to console {}".format(vc))
              except:
                print("UInput write error")

              ui.close()

    except KeyboardInterrupt:
      return 0

    except:
      uids_list = None
      sleep(2)	# Wait a bit before reconnecting



### Jump to the main routine
if __name__ == "__main__":
  main()
