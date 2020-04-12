#!/usr/bin/python3
"""Script to automatically lock and unlock a Cinnamon session with an
authentified NFC or RFID transponder. This script may easily be adapted to
other screensavers (Gnome's for example) by changing the lock, unlock and
status query commands in the parameters below.

This script is a SiRFIDaL client. It periodically requests the authentication
status of the current user from the SiRFIDaL server and works out when to lock
or unlock the user's graphical session.

To use the script, add it in "Preferences > Startup Applications" - or
wherever your desktop environment of choice lists things to launch when it
starts up. To activate the script, log out and back in or start it manually
from the menu.

The script can work in two different modes:

- "Persistent authentication" mode, i.e. session locking / unlocking depending
  on the continued presence of an authenticated UID from an NFC or RFID reader.
  This is useful with smartcards or NFC / RFID cards you leave in the reader to
  keep the session unlocked, and take out when you leave your desk to lock the
  session automatically. To use this mode, pass the -p or --authpersistent
  parameter on the command line

- "Authentication events" mode, i.e. session locking /unlocking triggererd by
  UID authentication events. This is useful for use with NFC / RFID tags or
  implants that you typically present briefly to a reader to lock or unlock the
  session. To use this mode, pass the -e or --authevents parameter on the
  command line

In both modes, you can define how long the script must wait before executing
a lock or unlock command, by passing the duration of the wait in seconds
with -l or --lockafter for locking, and -u or --unlockafter for unlocking. If
you don't want the script to execute a lock or an unlock command at all, pass a
duration of -1.

If you don't pass any parameters on the command line, by default the script
works in authentication events mode, waits 3 seconds to lock the session and
unlocks it immediately (0 second wait).

Note that unlocking the session manually with a password or with SiRFIDaL PAM
remains possible even if the automatic session locker is running.
"""

# Parameters
screen_locker_lock_command="cinnamon-screensaver-command -l"
screen_locker_unlock_command="cinnamon-screensaver-command -d"
screen_locker_query_command="cinnamon-screensaver-command -q"
screen_locker_query_command_locked_regex="is active"

default_lock_timeout=3
default_unlock_timeout=0
default_do_authpersistent=False
default_do_verbose=False

check_user_authentication_every=0.2 #s
check_session_locker_status_every=5 #s

socket_path="/tmp/sirfidal_server.socket"



# Modules
import re
import sys
import argparse
from time import sleep
from psutil import Process
from getpass import getuser
from datetime import datetime
from subprocess import Popen, PIPE
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_PASSCRED



# Constants
QUERY=0
LOCK=1
UNLOCK=2



# Functions
def execute_command(command=None, verbose=False):
  """Execute command to query the state of the session locker, lock or unlock
     the session. Return -1 in case of error, 0 or 1 after a query command to
     reflect the session locker's status. Print informative messages if needed
  """

  if command==QUERY:
    cmd=screen_locker_query_command
    if verbose:
      sys.stdout.write("Session locker query")
  elif command==LOCK:
    cmd=screen_locker_lock_command
    if verbose:
      sys.stdout.write("Session lock")
  elif command==UNLOCK:
    cmd=screen_locker_unlock_command
    if verbose:
      sys.stdout.write("Session unlock")
  else:
    if verbose:
      sys.stdout.write("No command!\n")
    return(-1)

  cmd_error=False
  try:
    p=Popen(cmd.split(), stdout=PIPE)
    query_result=p.communicate()[0].decode("utf-8")
    exit_status=p.returncode
  except:
    cmd_error=True
    pass

  if cmd_error or exit_status:
    cmd_error=True

  if cmd_error:
    if verbose:
      sys.stdout.write(': error running command "{}\n"'.format(cmd))
      sys.stdout.flush()
    return(-1)

  if command==QUERY:
    exit_status=1 if re.search(
	  screen_locker_query_command_locked_regex,
	  query_result
	) else 0

    if verbose:
      sys.stdout.write(": session is {}".format(
	    "locked" if exit_status else "unlocked"))

  if verbose:
    sys.stdout.write("\n")
    sys.stdout.flush()

  return(exit_status)



def main():
  """Main routine
  """

  # Get the PID of our parent process, to detect if it changes later on
  ppid=Process().parent()

  # Parse the command line arguments if we have parameters
  if len(sys.argv)>1:

    argparser=argparse.ArgumentParser()

    argparser.add_argument(
	  "-l", "--lockafter",
	  help="Delay in sec before issuing lock commands (-1 = disabled) "\
		"[default: {}]".format(default_lock_timeout),
	  type=int,
	  default=default_lock_timeout
	)
    argparser.add_argument(
	  "-u", "--unlockafter",
	  help="Delay in sec before issuing unlock commands (-1 = disabled) "\
		"[default: {}]".format(default_unlock_timeout),
	  type=int,
	  default=default_unlock_timeout
	)
    argparser.add_argument(
	  "-v", "--verbose",
	  help="Print lock/unlock commands "\
		"[default: {}]".format(default_do_verbose),
	  action="store_true",
	  default=default_do_verbose
	)

    mutexargs=argparser.add_mutually_exclusive_group()

    mutexargs.add_argument(
	  "-p", "--authpersistent",
	  help="Trigger session lock/unlock depending on the presence of an "\
		"authenticated UID"\
	 	"[default: {}]".format(default_do_authpersistent),
	  action="store_true",
	  default=default_do_authpersistent
	)
    mutexargs.add_argument(
	  "-e", "--authevents",
	  help="Trigger session lock/unlock upon UID authentication events "\
	 	"[default: {}]".format(not default_do_authpersistent),
	  action="store_true",
	  default=not default_do_authpersistent
	)

    args=argparser.parse_args()

    lock_timeout=args.lockafter
    unlock_timeout=args.unlockafter
    do_authpersistent=True if args.authpersistent else False
    do_verbose=args.verbose

    # If we have neither lock nor unlock timeouts, we have nothing to do!
    if lock_timeout<0 and unlock_timeout<0:
      print("Error: no lock or unlock timeouts - nothing to do!")
      return(-1)

  else:

    lock_timeout=default_lock_timeout
    unlock_timeout=default_unlock_timeout
    do_authpersistent=default_do_authpersistent
    do_verbose=default_do_verbose

  # Get the user's name
  user=getuser()

  session_locked=False	# Assume session locked without knowing better yet
  recheck_session_locked_tstamp=0
  sock=None

  user_authenticated=None
  sched_action=None
  sched_action_tstamp=None

  while True:

    cycle_start_tstamp=datetime.now().timestamp()

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
        sock.settimeout(check_user_authentication_every * 10)
      except:
        if sock:
          sock.close()
        sock=None
        sleep(1)
        continue

      crecvbuf=""

    # Send the request to the server
    try:
      sock.sendall("WAITAUTH {} 0\n".format(user).encode("ascii"))
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

      # Get data from the socket
      try:
        b=sock.recv(256).decode("ascii")
      except:
        sock.close()
        sock=None
        sleep(1)
        break

      # If we got nothing, the server has closed its end of the socket.
      if len(b)==0:
        sock.close()
        sock=None
        sleep(1)
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

    # Track user authentication status changes
    if last_user_authenticated == None:
      last_user_authenticated=user_authenticated
      last_auth_status_change_tstamp=cycle_start_tstamp

    if last_user_authenticated != user_authenticated:
      last_auth_status_change_tstamp=cycle_start_tstamp

    # Recheck the session's locked status periodically, and also when
    # the user's authentication status changes, to sync up our internal state
    # in case the user or the screensaver locked or unlocked the screen without
    # our knowing
    if cycle_start_tstamp > recheck_session_locked_tstamp or \
		last_user_authenticated != user_authenticated:

      session_locker_status=execute_command(command=QUERY, verbose=do_verbose)

      if session_locker_status > -1:
        session_locked=True if session_locker_status > 0 else False

      recheck_session_locked_tstamp=cycle_start_tstamp + \
				check_session_locker_status_every
    
    # Actions to schedule or clear in persistent authentication mode
    if do_authpersistent:

      if session_locked and sched_action != UNLOCK and \
		user_authenticated and unlock_timeout >= 0:
        sched_action=UNLOCK
        sched_action_tstamp=cycle_start_tstamp + unlock_timeout

      elif not session_locked and sched_action != LOCK and \
		not user_authenticated and lock_timeout >= 0:
        sched_action=LOCK
        sched_action_tstamp=cycle_start_tstamp + lock_timeout

      elif session_locked and sched_action!=None and not user_authenticated:
        sched_action=None
        sched_action_tstamp=None

      elif not session_locked and sched_action!=None and user_authenticated:
        sched_action=None
        sched_action_tstamp=None

    # Actions to schedule or clear in authentication events mode
    else:

      if not last_user_authenticated and user_authenticated and \
		session_locked and unlock_timeout >= 0:
        sched_action=UNLOCK
        sched_action_tstamp=cycle_start_tstamp + unlock_timeout

      elif not last_user_authenticated and user_authenticated and \
		not session_locked and lock_timeout >= 0:
        sched_action=LOCK
        sched_action_tstamp=cycle_start_tstamp + lock_timeout

      elif last_user_authenticated and not user_authenticated:
        sched_action=None
        sched_action_tstamp=None

    # Execute the action upon timeout
    if sched_action!=None and cycle_start_tstamp >= sched_action_tstamp:

      execute_command(command=sched_action, verbose=do_verbose)
      session_locked = sched_action==LOCK
      sched_action=None
      sched_action_tstamp=None

    # Sleep just long enough to update the user's authentication status more
    # or less regularly - if we're not already late to get the next status
    now=datetime.now().timestamp()
    if now < cycle_start_tstamp + check_user_authentication_every:
      sleep(cycle_start_tstamp + check_user_authentication_every - now)



# Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
