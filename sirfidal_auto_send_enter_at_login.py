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

For X logins, the script uses the wmctrl utility to determine if an X session
is already running. You can set the paths to wmctrl in the parameters below.
"""

### Modules
import re
import os
import psutil
from time import sleep
from evdev import UInput, ecodes
import sirfidal_client_class as scc

try:
  import Xlib.XK
  from Xlib import X
  from Xlib.protocol import event
  from Xlib.display import Display
  do_x = True
except:
  do_x = False



### Subroutines
def active_vc():
  """Return the name of the current virtual console or None in case of error.
  (Linux-specific)
  """

  try:
    with open("/sys/class/tty/tty0/active", "rb", buffering = 0) as f:
      active_vc = f.readline().decode("utf-8").strip()
  except:
    active_vc = None

  return active_vc



def is_console_session_running(vc):
  """Returns True if processes other than getty or login are attached to a
  virtual console, False if getty, login or both are attached but nothing else,
  and None in case of error
  """

  if not vc:
    return None

  getty_or_login_attached = False
  non_getty_or_login_attached = False

  for p in psutil.process_iter():

    if p.terminal() == "/dev/" + vc:
      if p.name() in ("getty", "agetty", "login"):
        getty_or_login_attached = True
      else:
        non_getty_or_login_attached = True

      if getty_or_login_attached and non_getty_or_login_attached:
        break

  if non_getty_or_login_attached:
    return True

  if getty_or_login_attached:
    return False

  return None



def xorg_attached_to_vc(vc):
  """Find an Xorg process attached to a virtual console and return the DISPLAY
  and Xauthority files attached to it. If no Xorg process is attached to the
  virtual terminal or in case of error, return (None, None)
  """

  display = None
  xauthfile = None

  if vc:

    for p in psutil.process_iter():
      if p.name() == "Xorg" and p.terminal() == "/dev/" + vc:

        next_arg_is_xauthfile = False

        for arg in p.cmdline():
          if re.match("^:[0-9]+$", arg):
            display = arg

          elif arg == "-auth":
            next_arg_is_xauthfile = True

          elif next_arg_is_xauthfile:
            xauthfile = arg
            next_arg_is_xauthfile = False

  return (display, xauthfile)



def open_x_display(display, xauthfile):
  """Open a connection to an X display. Return the Display object or None in
  case of failure
  """

  xauth_orig = os.environ.get("XAUTHORITY")
  os.environ["XAUTHORITY"] = xauthfile

  try:
    d = Display(display)
  except:
    d = None

  if xauth_orig:
    os.environ["XAUTHORITY"] = xauth_orig
  else:
    del(os.environ["XAUTHORITY"])

  return d



def is_wm_running(d, r):
  """ Returns True if an ICCM or EWMH window manager is running as the root
  window of an X display, False if no windows manager is found and None in case
  of error.
  """

  try:
    return r.get_full_property(d.intern_atom("_NET_SUPPORTING_WM_CHECK"),
				d.intern_atom("CARDINAL")) is not None or \
		r.get_full_property(d.intern_atom("_WIN_SUPPORTING_WM_CHECK"),
				d.intern_atom("CARDINAL")) is not None
  except:
    return None



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

            # If we do X: is an X server attached to the virtual console?
            if do_x:
              display, xauthfile = xorg_attached_to_vc(vc)

            if do_x and display is not None and xauthfile is not None:

                # Open the X display
                d = open_x_display(display, xauthfile)
                if d is not None:

                  # Get the root window
                  try:
                    r = d.screen().root
                  except:
                    r = None

                  # Check whether a ICCM or EWMH window manager is running on
                  # the X server - in which case we can be reasonably sure a
                  # session is already open. If the check succeeds and no
                  # window manager is present, send a Return key event. Abstain
                  # in case of error, or if a window manager is running
                  if r is not None and is_wm_running(d, r) == False:

                    # Send Return to the X window currently in focus - i.e. the
                    # display manager, since nothing else should be displayed
                    try:
                      enter_keysym = Xlib.XK.string_to_keysym("Return")
                      enter_keycode = d.keysym_to_keycode(enter_keysym)
                      f = d.get_input_focus().focus
                      f.send_event(event.KeyPress(detail = enter_keycode,
						time = 0,
						root = r, window = f,
                                                same_screen = 0,
						child = X.NONE,
						root_x = 0, root_y = 0,
						event_x = 0, event_y = 0,
						state = 0))
                      f.send_event(event.KeyRelease(detail = enter_keycode,
						time = 0,
						root = r, window = f,
                                                same_screen = 0,
						child = X.NONE,
						root_x = 0, root_y = 0,
						event_x = 0, event_y = 0,
						state = 0))
                      print("Return sent to the X window")
                    except:
                      print("Error sending Return keysym to the X window")

                  # Close the X display
                  try:
                    d.close()
                  except:
                    pass

            # Is getty and/or login attached to the virtual console and no
            # session open?
            elif is_console_session_running(vc) == False:

              # Send the keystroke sequence corresponding to ENTER to the
              # console
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

    except KeyboardInterrupt:
      return 0

#    except:
#      uids_list = None
#      sleep(2)	# Wait a bit before reconnecting



### Jump to the main routine
if __name__ == "__main__":
  main()
