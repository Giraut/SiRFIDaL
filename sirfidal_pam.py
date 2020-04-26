#!/usr/bin/python3
"""PAM module to do user authentication using an RFID or NFC transponder.

This script is a SiRFIDaL client. It is normally meant to be called by the
pam_exec.so PAM module, but you may use it directly or in your own scripts also.

It forwards the PAM authentication request, along with a delay for successful
authentication, to the SiRFIDaL server, then waits for the authentication status
reply from the server.

The delay for successful authentication may be specified with the -w argument.
If unspecified, the delay is 2 seconds.

PAM needs to be configured to use this script as a PAM module. Typically, with
Linux PAM, if you want to do single factor authentication (password *OR* RFID),
you want to do the following configuration:

- Add a configuration file in /usr/share/pam-configs for this PAM module
(for example /usr/share/pam-configs/sirfidal_pam.config) with the following
lines:

Name: SiRFIDaL RFID / NFC UID authentication
Default: yes
Priority: 192
Auth-Type: Primary
Auth:
  [success=end default=ignore]  pam_exec.so quiet /usr/local/bin/sirfidal_pam.py
Auth-Initial:
  [success=end default=ignore]  pam_exec.so quiet /usr/local/bin/sirfidal_pam.py

The priority level specified in this file should be lower than the priority
level of pam_unix (normally found in /usr/share/pam-configs/unix), so that
pam_unix.so runs first.

- Modify /usr/share/pam-configs/unix to disable pam_unix.so's
default delay-on-failure. Simply add "nodelay" after all "pam_unix.so" on all
the Auth lines. For example:

Auth:
  [success=end default=ignore]  pam_unix.so nodelay nullok_secure try_first_pass
Auth-Initial:
  [success=end default=ignore]	pam_unix.so nodelay nullok_secure

In effect, doing so replaces pam_unix.so's "useless" wait with SiRFIDaL's
"useful" RFID / NFC authentication delay. That way, if you log in regularly
with a password and the login fails, you won't see a difference. But if the
primary Unix login fails, you can use the subsequent delay to present your RFID
or NFC transponder to log in.

So typically, if you only want to log in with your transponder, simply press
ENTER to dismiss the regular Unix password, then present your transponder
within the 2 second delay. Or present your transponder first then dismiss the
regular Unix password prompt with ENTER to log in immediately.

Once you have created /usr/share/pam-configs/sirfidal_pam.config and modified
/usr/share/pam-configs/unix, commit the changes by invoking:

pam-auth-update

Of course, to log in successully, the SiRFIDaL server must be running, and the
user must have been added to the encrypted UIDs file (see sirfidal_useradm.py).

If you'd rather do two-factor authentication (2FA - i.e. login is allowed
with a password *AND* RFID), replace "success=end" with "success=ok" in
/usr/share/pam-configs/unix

See README.example_PAM_scenarios for more PAM configuration options.
"""

### Parameters
default_auth_wait=2 #s
socket_path="/tmp/sirfidal_server.socket"



### Modules
import os
import sys
import argparse
from time import sleep
from datetime import datetime
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_PASSCRED



### Classes
class ArgumentParser(argparse.ArgumentParser):
  """Override the default error exit status of the argument parser, to prevent
  it from authentifying the user in case of an argument error when run from
  pam_exec.so
  """

  def error(self, status=0, message=None):
    super(ArgumentParser, self).print_help()
    self.exit(-1)

  def print_help(self):
    super(ArgumentParser, self).print_help()
    self.exit(-1)



### Main routine
def main():
  """Main routine
  """

  # Get the PAM_USER environment variable. If we don't have it, we're
  # not being called by pam_exec.so, so get the USER environment variable
  # instead
  pam_user=os.environ["PAM_USER"] if "PAM_USER" in os.environ else \
		os.environ["USER"] if "USER" in os.environ else None

  # Read the command line arguments
  argparser=ArgumentParser()
  argparser.add_argument(
	  "-w", "--wait",
	  type=float,
	  help="Delay (s) to wait for a UID that authenticates the user " \
		"(default {})".format(default_auth_wait),
          required=False
	)
  argparser.add_argument(
	  "-u", "--user",
	  type=str,
	  help="Username to override the PAM_USER environment variable",
          required=False
	)
  args=argparser.parse_args()

  wait_secs=args.wait if args.wait!=None else default_auth_wait
  wait_secs=wait_secs if wait_secs >= 0 else 0
  pam_user=args.user if args.user else pam_user

  # Fail if we don't have a user to authenticate
  if not pam_user:
    print("Error: no username to authenticate")
    return(-1)
  
  # Open a socket to the auth server
  try:
    sock=socket(AF_UNIX, SOCK_STREAM)
  except:
    sleep(wait_secs)
    print("Error: socket timeout")
    return(-2)
  try:
    sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
  except:
    sleep(wait_secs)
    print("Error: socket setup")
    return(-3)
  try:
    sock.connect(socket_path)
  except:
    sleep(wait_secs)
    print("Error: socket connect")
    return(-4)

  # Make sure we never get stuck on an idle server
  sock.settimeout(wait_secs + 5)

  endwait_tstamp=datetime.now().timestamp() + wait_secs

  # Send the authentication request to the server
  try:
    sock.sendall("WAITAUTH {} {}\n".format(pam_user, wait_secs).encode("ascii"))
  except:
    left_to_wait=endwait-datetime.now().timestamp()
    sleep(left_to_wait if left_to_wait > 0 else 0)
    print("Error: socket send")
    return(-5)

  # Get the reply - one line only
  server_reply=""
  got_server_reply=False

  while not got_server_reply:

    # Get data from the socket
    try:
      b=sock.recv(256).decode("ascii")
    except timeout:
      print("Error: socket receive timeout")
      return(-6)
    except:
      left_to_wait=endwait-datetime.now().timestamp()
      sleep(left_to_wait if left_to_wait > 0 else 0)
      print("Error: socket receive")
      return(-7)

    # If we got nothing, the server has closed its end of the socket.
    if len(b)==0:

      sock.close()
      left_to_wait=endwait-datetime.now().timestamp()
      sleep(left_to_wait if left_to_wait > 0 else 0)
      print("Error: socket unexpectedly closed")
      return(-8)

    # Read one CR- or LF-terminated line
    for c in b:

      if c=="\n" or c=="\r":
        got_server_reply=True
        break

      elif len(server_reply)<256 and c.isprintable():
        server_reply+=c

  sock.close

  # Print the server's reply (without UID if it was sent by the server) and
  # return the authentication status
  if server_reply[:6]=="AUTHOK":
    print(server_reply[:6])
    return(0)
  else:
    print(server_reply)
    return(1)



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
