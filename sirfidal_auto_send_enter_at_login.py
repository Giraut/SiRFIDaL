#!/usr/bin/python3
"""Utility to automatically type ENTER in a virtual console (text) or in a
X display manager login screen (graphical) when SiRFIDaL reads a RFID or NFC
UID.

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

THIS SCRIPT MUST BE RUN AS ROOT!

It uses the sirfidal_getuids utility, and in the case of X logins, the wmctrl
utility to determine if an X session is already running. You can set the paths
to the sirfidal_getuids and wmctrl utilities in the parameters section below.
"""

### Parameters
sirfidal_getuids="/usr/local/bin/sirfidal_getuids.py"
wmctrl="/usr/bin/wmctrl"



### Modules
import re
import os
import psutil
from time import sleep
from evdev import UInput, ecodes
from subprocess import Popen, DEVNULL, PIPE
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



### Subroutines
def active_vc():
  """Return the name of the current virtual console or None in case of error.
  (Linux-specific)
  """
  try:
    with open("/sys/class/tty/tty0/active", "rb", buffering=0) as f:
      active_vc=f.readline().decode("utf-8").strip()
  except:
    active_vc=None

  return(active_vc)



def is_console_session_running(vc):
  """Returns True if processes other than getty or login are attached to a
  virtual console, False if getty, login or both are attached but nothing else,
  and None in case of error
  """

  if not vc:
    return(None)

  getty_or_login_attached=False
  non_getty_or_login_attached=False

  for p in psutil.process_iter():

    if p.terminal()=="/dev/"+vc:
      if p.name() in ["getty", "agetty", "login"]:
        getty_or_login_attached=True
      else:
        non_getty_or_login_attached=True

      if getty_or_login_attached and non_getty_or_login_attached:
        break

  if non_getty_or_login_attached:
    return(True)

  if getty_or_login_attached:
    return(False)

  return(None)



def xorg_attached_to_vc(vc):
  """Find an Xorg process attached to a virtual console and return the DISPLAY
  and Xauthority files attached to it. If no Xorg process is attached to the
  virtual terminal or in case of error, return (None, None)
  """

  display=None
  xauthfile=None

  if vc:

    for p in psutil.process_iter():
      if p.name()=="Xorg" and p.terminal()=="/dev/"+vc:

        next_arg_is_xauthfile=False

        for arg in p.cmdline():
          if re.match("^:[0-9]+$", arg):
            display=arg

          elif arg=="-auth":
            next_arg_is_xauthfile=True

          elif next_arg_is_xauthfile:
            xauthfile=arg
            next_arg_is_xauthfile=False

  return(display, xauthfile)



def is_wm_running(display, xauthfile):
  """ Returns True if a window manager is running on an X display, False if
  no windows manager is found (indicating that no session is open, only the
  display manager is running and presumably waiting for a login) or None in
  case of error.
  """

  if not display or not xauthfile:
   return(None)

  try:
    wmctrl_output = b"\n".join(Popen([wmctrl, "-m"],
		env={"DISPLAY": display, "XAUTHORITY": xauthfile},
		stdout=PIPE, stderr=PIPE).communicate()).decode("utf-8")
  except:
    return(None)

  if re.search("Cannot get window manager info", wmctrl_output, re.I):
    return(False)

  if re.search("PID", wmctrl_output, re.I):
    return(True)

  return(None)

          

### Main routine
def main():
  """Main routine
  """

  getuids_proc=None

  while True:

    # Try to spawn a sirfidal_getuids process
    if not getuids_proc:
      print("Spawning {}...".format(sirfidal_getuids))
      try:
        getuids_proc=Popen([sirfidal_getuids, "-q"], bufsize=0,
				stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL)
      except KeyboardInterrupt:
        return(-1)
      except:
        print("Error spawning: {}".format(sirfidal_getuids))
        getuids_proc=None
        sleep(2)	# Wait a bit before trying to respawn a new process
        continue

    # Read one character from the sirfidal_getuids process
    try:
      c=getuids_proc.stdout.read(1)
    except KeyboardInterrupt:
      return(-1)
    except:
      c=None

    if not c:
      if getuids_proc:
        try:
          getuidsproc.kill()
        except:
          pass
        getuids_proc=None
      print("Error: {} has stopped. Are you root?".format(sirfidal_getuids))
      sleep(2)	# Wait a bit before trying to respawn a new process
      continue

    # Carry on reading until we get a newline
    if c!=b"\n":
      continue

    # Find out the active virtual console
    vc=active_vc()
    if not vc:
      print("Error determining the active virtual console")
      continue

    # Is an X server attached to the virtual console?
    display, xauthfile = xorg_attached_to_vc(vc)
    if display and xauthfile:
    
      # If a window manager is running on the X server, a session is already
      # open, so give up. Also give up in case of error checking the display
      # manager
      if is_wm_running(display, xauthfile)!=False:
        continue

      # Point DISPLAY and XAUTHORITY to the X server
      display_prev=os.environ.get("DISPLAY")
      xauthority_prev=os.environ.get("XAUTHORITY")

      os.environ["DISPLAY"]=display
      os.environ["XAUTHORITY"]=xauthfile

      # Send ENTER to the display manager
      s="\r"
      msg=None

      if typer=="xdo":
        try:
          xdo().enter_text_window(s)
          msg="ENTER sent to display {}".format(display)
        except:
          msg="Error sending ENTER to display {} using xdo".format(display)

      elif typer=="pynput":
        try:
          kbd=Controller()
          kbd.type(s)
          msg="ENTER sent to display {}".format(display)
        except:
          msg="Error sending ENTER to display {} using pynput".format(display)

      else:
        msg="Error: no usable typer module. Install xdo or pynput"

      # Restore or unset the previous DISPLAY and XAUTHORITY variables
      if display_prev:
        os.environ["DISPLAY"]=display_prev
      else:
        os.environ.pop("DISPLAY")
      if xauthority_prev:
        os.environ["XAUTHORITY"]=xauthority_prev
      else:
        os.environ.pop("XAUTHORITY")

      # Print any error message
      if msg:
        print(msg)

    # Is getty and/or login attached to the virtual console and no session
    # open?
    elif is_console_session_running(vc)==False:

      # Send the keystroke sequence corresponding to ENTER to the console
      try:
        ui = UInput()
      except:
        print("UInput open error: are you root?")
        continue

      try:
        ui.write(ecodes.EV_KEY, ecodes.KEY_ENTER, 1)
        ui.write(ecodes.EV_KEY, ecodes.KEY_ENTER, 0)
        ui.syn()
        print("ENTER sent to console {}".format(vc))
      except:
        print("UInput write error")
        
      ui.close()



### Jump to the main routine
if __name__ == "__main__":
  main()
