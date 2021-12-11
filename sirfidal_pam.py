#!/usr/bin/python3
"""PAM module to do user authentication using an RFID or NFC transponder.

This script is a SiRFIDaL client. It may be used in 3 different ways:

- Called by the pam_python.so PAM module
- Called by the pam_exec.so PAM module
- As a command line utility

If used as a PAM module, it is preferable to use it with pam_python
(http://pam-python.sourceforge.net/), as it is able to set the authentication
token (authtok) for use by other PAM modules further down the PAM stack -
particularly pam_gnome_keyring.so to unlock the keyring automatically
using the authenticating RFID or NFC UID as keyring password.

Unfortunately, pam_python does not come pre-built in all Linux distributions.
In particular, RPM-based distributions (such as Fedora) don't include it. So
this module is also compatible with pam_exec.so, which comes with all Linux
distributions, as a lowest common denominator mode of operation. However, it
won't be able to set authtok when run from pam_exec.so.

The module forwards the PAM authentication request, along with a delay for
successful authentication, to the SiRFIDaL server, then waits for the
authentication status reply from the server.

The delay for successful authentication may be specified with the -w argument
or wait= argument. If unspecified, the delay is 2 seconds.

The username to authenticate is normally obtained from PAM, but it may be
overridden using the -u or user= argument.

PAM needs to be configured to use this script as a PAM module. Typically, with
Linux PAM, if you want to do single factor authentication (password *OR* RFID),
you want to do the following configuration:

- Add a configuration file in /usr/share/pam-configs for this PAM module
  (for example /usr/share/pam-configs/sirfidal_pam.config) with the following
  lines:

  * Use with the pam_python.so PAM module:

Name: SiRFIDaL RFID / NFC UID authentication
Default: yes
Priority: 192
Auth-Type: Primary
Auth:
  [success=end default=ignore]  pam_python.so /usr/local/bin/sirfidal_pam.py
Auth-Initial:
  [success=end default=ignore]  pam_python.so /usr/local/bin/sirfidal_pam.py

  * Use with the pam_exec.so:

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
  primary Unix login fails, you can use the subsequent delay to present your
  RFID or NFC transponder to log in.

  So typically, if you only want to log in with your transponder, simply press
  ENTER to dismiss the regular Unix password, then present your transponder
  within the 2 second delay. Or present your transponder first then dismiss the
  regular Unix password prompt with ENTER to log in immediately.

- Once you have created /usr/share/pam-configs/sirfidal_pam.config and modified
  /usr/share/pam-configs/unix, commit the changes by invoking:

  pam-auth-update

Of course, to log in successully, the SiRFIDaL server must be running, and the
user must have been added to the encrypted UIDs file (see sirfidal_useradm.py).

If you'd rather do two-factor authentication (2FA - i.e. login is allowed
with a password *AND* RFID), replace "success=end" with "success=ok" in
/usr/share/pam-configs/unix

See README.example_PAM_scenarios for more PAM configuration options.
"""

### Modules
import os
import sys
from time import time, sleep



### Common routines
def parse_args(argv, wait_secs, pam_user):
  """Parse the command line arguments. Return (errmsg, wait_secs, user), with
  errmsg being None if the arguments were parsed successfully"""

  next_arg_is_wait = False
  next_arg_is_user = False

  for arg in argv[1:]:

    if arg in ("-h", "--help"):
      return ("\n".join([
	"",
	"Usage: {}".format(argv[0]),
	"",
	"       -w <wait> or	Delay (s) to wait for a UID that authenticate",
	"       waitr=<wait>	the user - Default {}".format(wait_secs),
	"",
	"       -u <user> or	Username to override the PAM_USER environment",
	"       user=<user>	variable",
	"",
	"       -h or --help	This help",
	""]), None, None)

    elif arg == "-w":
      next_arg_is_wait = True

    elif arg == "-u":
      next_arg_is_user = True

    elif arg[:5] == "wait=":
      try:
        wait_secs = max(0, float(arg[5:]))
      except:
        return ("Error: invalid wait= value: {}".format(arg[5:]), None, None)

    elif arg[:5] == "user=":
      pam_user = arg[5:]
      if not all([" " <= c <= "~" for c in pam_user]):
        return ("Error: invalid user= value: {}".format(arg[5:]), None, None)

    elif next_arg_is_wait:
      try:
        wait_secs = max(0, float(arg))
      except:
        return ("Error: invalid -w value: {}".format(arg), None, None)
      next_arg_is_wait = False

    elif next_arg_is_user:
      pam_user = arg
      if not all([" " <= c <= "~" for c in pam_user]):
        return ("Error: invalid -u value: {}".format(arg), None, None)
      next_arg_is_user = False

    else:
      return ("Error: unknown argument: {}".format(arg), None, None)

  if next_arg_is_wait:
    return ("Error: missing -w value", None, None)

  elif next_arg_is_user:
    return ("Error: missing -u value", None, None)

  # Fail if we don't have a user to authenticate
  if not pam_user:
    return ("Error: no username to authenticate", None, None)

  return (None, wait_secs, pam_user)



### Callbacks for use when run from pam_python.so
# Unhandled PAM functions
def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_CRED_UNAVAIL

def pam_sm_acct_mgmt(pamh, flags, argv):
  return pamh.PAM_ACCT_EXPIRED

def pam_sm_chauthtok(pamh, flags, argv):
  return pamh.PAM_AUTHTOK_ERR

def pam_sm_open_session(pamh, flags, argv):
  return pamh.PAM_SYSTEM_ERR

def pam_sm_close_session(pamh, flags, argv):
  return pamh.PAM_SYSTEM_ERR

# Handled PAM functions
def pam_sm_authenticate(pamh, flags, argv):

  # Add the absolute path to the directory this module lives in and add it
  # to the Python search path, to import the SiRFIDaL client class file that
  # should reside in the same directory, as pam_python.so doesn't do it
  sys.path.append((os.path.dirname(os.path.abspath(argv[0]))))

  # Import the SiRFIDaL client class
  import sirfidal_client_class as scc

  # Get the username
  try:
    pam_user = pamh.get_user()
  except pamh.exception:
    pam_user = None
  if pam_user is None:
    return pamh.PAM_USER_UNKNOWN

  # Parse the command line arguments
  errmsg, wait_secs, pam_user = parse_args(argv,
					scc._sirfidal_default_auth_wait,
					pam_user)
  if errmsg is not None:
    try:
      pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG, errmsg))
    except:
      pass
    return pamh.PAM_SYSTEM_ERR

  endwait = time() + wait_secs

  try:

    # Connect to the SiRFIDaL server
    with scc.sirfidal_client() as sc:

      # Get the user's authentication status and authentication UIDs (if any)
      authok, uids = sc.waitauth(user = pam_user, wait = wait_secs)

      # Was the user authenticated?
      if authok:

        # If the server returned authenticating UIDs, set the authentication
        # token to the first one for further use in the PAM stack
        if uids:
          pamh.authtok = uids[0]

        return pamh.PAM_SUCCESS

      # The user was not authenticated
      else:

        # Continue to wait until the complete authentication delay has elapsed
        sleep(max(0, endwait - time()))

        return pamh.PAM_AUTH_ERR

  except Exception as e:

    # Continue to wait until the complete authentication delay has elapsed
    sleep(max(0, endwait - time()))

    try:
      pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG,
				"sirfidal_pam error: {}".format(e)))
    except:
      pass

    return pamh.PAM_SYSTEM_ERR



### Main routine for use when run from pam_exec.so or on the command line
def main():
  """Main routine
  """

  # Import the SiRFIDaL client class
  import sirfidal_client_class as scc

  # Get the PAM_USER environment variable. If we don't have it, we're
  # not being called by pam_exec.so, so get the USER environment variable
  # instead
  pam_user = os.environ["PAM_USER"] if "PAM_USER" in os.environ else \
		os.environ["USER"] if "USER" in os.environ else None

  # Parse the command line arguments
  errmsg, wait_secs, pam_user = parse_args(sys.argv,
					scc._sirfidal_default_auth_wait,
					pam_user)
  if errmsg is not None:
    print(errmsg)
    return -1

  # Authenticate the user. Wait the number of seconds regardless in case of
  # error or failed authentication
  endwait = time() + wait_secs

  try:

    # Connect to the SiRFIDaL server
    with scc.sirfidal_client() as sc:

      # Was the user authenticated?
      if sc.waitauth(user = pam_user, wait = wait_secs)[0]:

        print("AUTHOK")
        return 0

      # The user was not authenticated
      else:

        # Continue to wait until the complete authentication delay has elapsed
        sleep(max(0, endwait - time()))

        print("NOAUTH")
        return 1

  except Exception as e:

    # Continue to wait until the complete authentication delay has elapsed
    sleep(max(0, endwait - time()))

    print("Error: {}".format(e))
    return 1



### Jump to the main routine - For use when run from pam_exec.so or on the
### command line
if __name__ == "__main__":
  sys.exit(main())
