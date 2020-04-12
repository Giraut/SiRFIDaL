#!/usr/bin/python3
"""PAM module for user authentication using an RFID or NFC transponder.

This script is a SiRFIDaL client. It is not meant to be called directly, but
by the pam_exec.so PAM module. It forward the PAM authentication request, along
with a delay for successful authentication, to the SiRFIDaL server, then wait 
for the authentication status reply from the server.

The delay for successful authentication may be specified with the -w argument.
If unspecified, the delay is 2 seconds.

PAM needs to be configured to use this script. Typically, with Linux PAM, if
you want to do single factor authentication (password *OR* RFID), you want to
do the following configuration:

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
or NFC tag to log in.

So typically, if you only want to log in with your tag, simply press ENTER to
dismiss the regular Unix password, then present your tag within the 2 second
delay. Or present your tag first then dismiss the regular Unix password prompt
with ENTER to log in immediately.

Once you have created /usr/share/pam-configs/sirfidal_pam.config and modified
/usr/share/pam-configs/unix, commit the changes by invoking:

pam-auth-update

Of course, to log in successully, the SiRFIDaL server must be running, and the
user must have been added to the encrypted UIDs file (see sirfidal_useradm.py).

If you'd rather do two-factor authentication (2FA - i.e. login is allowed
with a password *AND* RFID), replace "success=end" with "success=ok" in
/usr/share/pam-configs/unix
"""

### Parameters
default_auth_wait=2 #s
socket_path="/tmp/sirfidal_server.socket"



### Modules
import os
import sys
import argparse
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
  # not being called by pam_exec.so, so give up with an error message
  pam_user=os.environ["PAM_USER"] if "PAM_USER" in os.environ else None
  if not pam_user:
    print("Error: this script is meant to be called by pam_exec.so, " \
		"not directly")
    return(-1)
  
  # Read the command line arguments
  argparser=ArgumentParser()
  argparser.add_argument(
	  "-w", "--wait",
	  type=float,
	  help="Delay (s) to wait for a card that authenticates the user " \
		"(default {})".format(default_auth_wait),
          required=False
	)
  args=argparser.parse_args()

  wait_secs=args.wait if args.wait!=None else default_auth_wait

  # Open a socket to the auth server
  try:
    sock=socket(AF_UNIX, SOCK_STREAM)
  except:
    return(-2)
  try:
    sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
  except:
    return(-3)
  try:
    sock.connect(socket_path)
  except:
    return(-4)

  # Make sure we never get stuck on an idle server
  sock.settimeout((wait_secs if wait_secs >=0 else 0) + 5)

  # Send the authentication request to the server
  try:
    sock.sendall("WAITAUTH {} {}\n".format(pam_user, wait_secs).encode("ascii"))
  except:
    return(-5)

  # Get the reply - one line only
  server_reply=""
  got_server_reply=False

  while not got_server_reply:

    # Get data from the socket
    try:
      b=sock.recv(256).decode("ascii")
    except timeout:
      return(-6)
    except:
      return(-7)

    # If we got nothing, the server has closed its end of the socket.
    if len(b)==0:

      sock.close()
      return(-8)

    # Read one CR- or LF-terminated line
    for c in b:

      if c=="\n" or c=="\r":
        got_server_reply=True
        break

      elif len(server_reply)<256 and c.isprintable():
        server_reply+=c

  sock.close
  
  # Return the authentication status to pam_exec.so
  return(0 if server_reply=="AUTHOK" else 1)



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
