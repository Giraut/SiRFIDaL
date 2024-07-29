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
  If several sessions are found running on the same console (normally
  impossible), "greeter" class supersedes other classes.
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
    m = re.findall(r"^\s*(\S+)\s+([0-9]+)\s+([!-,\.0-9;A-~]{1,32})\s+.*$", l)
    if m:
      sessionids.append(m[0][0])

  session_class = ""

  # For each session, get the associated virtual console and class
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
    # doesn't match. Remember the class if it does, and return immediately if
    # the class is "greeter".
    tty = None
    sc = None

    for l in loginctl_stdout.split("\n"):

      m = re.findall(r"^(VTNr|Class)=([\S+]+)$", l)
      if m:

        if m[0][0] == "VTNr":
          tty = "tty{}".format(m[0][1])
        else:
          sc = m[0][1]

        if tty is not None:

          if tty != vc:
            break

          elif sc is not None:
            if sc == "greeter":
              return sc
            else:
              session_class = sc
              break

  # We didn't find a session with a matching virtual console number
  return session_class



### Main routine
def main():
  """Main routine
  """

  while True:

    try:

      # Connect to the server
      with scc.sirfidal_client() as sc:

        # Watch the number of active UIDs
        for _, chg in sc.watchnbuids():

          # Has the number of active UIDs increased?
          if chg > 0:

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
              except Exception as e:
                print("UInput open error: {}".format(e))
                continue

              try:
                ui.write(ecodes.EV_KEY, ecodes.KEY_ENTER, 1)
                ui.syn()
                sleep(.1)   # Pause needed for gdm
                ui.write(ecodes.EV_KEY, ecodes.KEY_ENTER, 0)
                ui.syn()
                sleep(.1)   # Pause needed for gdm
                print("ENTER sent to console {}".format(vc))
              except Exception as e:
                print("UInput write error: {}".format(e))

              ui.close()

    except KeyboardInterrupt:
      return 0

    except:
      uids_list = None
      sleep(2)	# Wait a bit before reconnecting



### Jump to the main routine
if __name__ == "__main__":
  main()
