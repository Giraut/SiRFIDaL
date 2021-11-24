#!/usr/bin/python3
"""SiRFIDaL client class
"""

### Parameters
_sirfidal_default_server_socket_path = "/tmp/sirfidal_server.socket"
_sirfidal_default_global_config_file = "/etc/sirfidal_clients_parameters.py"
_sirfidal_default_user_config_file = "~/.sirfidal_clients_parameters.py"
_sirfidal_default_auth_wait = 2
_sirfidal_default_useradm_uid_read_wait = 5



### Modules
import os
import re
import pwd
import socket



### Constants
# Command replies
WRITEERR = -4
EXISTS   = -3
NONE     = -2
TIMEOUT  = -1
NOAUTH   = 0
OK       = 1
AUTHOK   = 1



### Routines
def load_parameters(client_name, global_config_file = \
			_sirfidal_default_global_config_file,
			user_config_file = _sirfidal_default_user_config_file):
  """Load a set of parameters from a sirfidal_clients_params dictionary, first
  located in global_config_file, then in user_config_file. All the key / values
  pairs are loaded in global().
  """

  errmsg = ""
  load_success = False

  for f in (global_config_file, user_config_file):
    try:
      exec(open(os.path.expanduser(f)).read())
      client_params = locals()["sirfidal_clients_params"][client_name]
      load_success = True
      for k in client_params:
        globals()[k] = client_params[k]
    except Exception as e:
      errmsg += (". Then e" if errmsg else "E") + \
			"rror loading {}: {}".format(f, e)

  if not load_success:
    raise RuntimeError(errmsg)



### Classes
class sirfidal_client:

  ### Variables
  _sock = None



  ### Methods
  def __init__(self, connect = True,
		socket_path = _sirfidal_default_server_socket_path):
    """__init__ method
    """

    if connect:
      self.connect(socket_path = socket_path)



  def __enter__(self):
    """__enter__ method
    """

    return self



  def connect(self, socket_path = _sirfidal_default_server_socket_path):
    """Connect to the SiRFIDaL server
    """

    # Open a socket to the auth server
    self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    self._sock.connect(socket_path)

    return self._sock



  def _command(self, cmd = None, timeout = None):
    """Send a command string to the SiFRIDaL server and return the reply.
    If cmd is None, only get a reply.
    """

    if cmd is not None:

      # Set the socket's timeout
      self._sock.settimeout(timeout)

      # Send the command
      self._sock.sendall((cmd + "\n").encode("ascii"))

    # Get the reply
    reply = ""

    while True:

      # Get data from the socket
      b = self._sock.recv(256).decode("ascii")

      # If we got nothing, the server has closed its end of the socket.
      if not b:
        raise TimeoutError("connection unexpectedly closed")

      # Read one LF-terminated line
      for c in b:

        if c == "\n":
          return reply

        elif c.isprintable() and len(reply)<256:
          reply += c


  def waitauth(self, user = None, wait = _sirfidal_default_auth_wait):
    """Authenticate a user. If user is None, use the current username. If wait
    isn't specified, use the default wait for authentication.
    Return (AUTHOK, []) if the user is simply authenticated,
    (AUTHOK, [UID #1, UID #2, ...]) if the user is authenticated and is allowed
    to know which UID(s) authenticated them, or (NOAUTH, []) if the user is
    not authenticated.
    NOAUTH is 0 and AUTHOK is not 0, so the result may be tested directly as a
    condition
    """

    # Check the wait parameter
    if wait < 0:
      raise ValueError("invalid wait")

    # Get the current username if the user isn't specified
    if user is None:
      user = pwd.getpwuid(os.getuid()).pw_name

    # Check that the username is valid
    if not user and user.isprintable():
      raise ValueError("invalid username")

    # Send the WAITAUTH command to the server and get the reply
    reply = self._command("WAITAUTH {} {}".format(user, wait),
				timeout = wait + 5)

    # Check that the reply is valid
    if re.search("^(NOAUTH|AUTHOK( +[0-9a-fA-F]+)*)$", reply):
      f = reply.upper().split()
      return (AUTHOK, f[1:]) if f[0] == "AUTHOK" else (NOAUTH, [])

    else:
      raise ValueError("unknown server reply '{}'".format(reply))



  def _useradm(self, cmd, user, wait):
    """Manipulate the user <-> UIDs association: associate a user and a UID
    (ADDUSER), disassociate a user from a UID (DELUSER with wait > 0) or
    disassociate a user from all UIDs (DELUSER with wait < 0). If user is None,
    use the current username.
    Return OK, NOAUTH, WRITEERR, TIMEOUT, EXISTS or NONE depending on the
    command.
    OK is > 0 while the other error codes are <= 0, so the command's success
    may be tested with a comparison with zero.
    """

    # Get the current username if the user isn't specified
    if user is None:
      user = pwd.getpwuid(os.getuid()).pw_name

    # Check that the username is valid
    if not user and user.isprintable():
      raise ValueError("invalid username")

    # Send the command to the server and get the reply
    reply = self._command("{} {} {}".format(cmd, user, wait),
				timeout = max(5, wait + 5))

    # Check that the reply is valid and return the appropriate return value
    if reply == "OK":
      return OK
    elif reply == "NOAUTH":
      return NOAUTH
    elif reply == "WRITEERR":
      return WRITEERR
    elif reply == "TIMEOUT" and \
		(cmd == "ADDUSER" or (cmd == "DELUSER" and wait >= 0)):
      return TIMEOUT
    elif reply == "EXISTS" and cmd == "ADDUSER":
      return EXISTS
    elif reply == "NONE" and cmd == "DELUSER":
      return NONE

    raise ValueError("unknown server reply '{}'".format(reply))



  def adduser(self, user = None, wait = _sirfidal_default_auth_wait):
    """Associate a user and a UID. If user is None, use the current username.
    If wait isn't specified for commands that use it, use the default wait time
    for scanning a UID.
    Return OK, NOAUTH, WRITEERR, TIMEOUT or EXISTS
    OK is > 0 while the other error codes are <= 0, so the command's success
    may be tested with a comparison with zero.
    """

    # Check the wait parameter
    if wait < 0:
      raise ValueError("invalid wait")

    return self._useradm("ADDUSER", user, wait)



  def deluser(self, user = None, wait = _sirfidal_default_auth_wait):
    """Disassociate a user from a UID. If user is None, use the current
    username. If wait isn't specified for commands that use it, use the
    default wait time for scanning a UID.
    Return OK, NOAUTH, WRITEERR, TIMEOUT or NONE
    OK is > 0 while the other error codes are <= 0, so the command's success
    may be tested with a comparison with zero.
    """

    # Check the wait parameter
    if wait < 0:
      raise ValueError("invalid wait")

    return self._useradm("DELUSER", user, wait)



  def delalluser(self, user = None):
    """Delete all user <-> UIDs associations for a user. If user is None, use
    the current username.
    Return OK, NOAUTH, WRITEERR, TIMEOUT or NONE
    OK is > 0 while the other error codes are <= 0, so the command's success
    may be tested with a comparison with zero.
    """

    return self._useradm("DELUSER", user, -1)



  def watchnbuids(self, timeout = None):
    """Watch the number of active UIDs in real-time.
    If timeout is not None, an exception will be raised if no update is
    received in time.
    Yield (Total nb of UIDs, delta)
    """

    reply = self._command("WATCHNBUIDS", timeout = timeout)

    while True:

      m = re.findall("^NBUIDS +(\+?[0-9]+) +([-\+]?[0-9]+)$", reply)
      if m:
        yield (int(m[0][0]), int(m[0][1]))
      else:
        raise ValueError("unknown server reply '{}'".format(reply))

      reply = self._command()



  def watchuids(self, timeout = None):
    """Watch the list of active UIDs in real-time.
    If timeout is not None, an exception will be raised if no update is
    received in time.
    Yield (AUTHOK, [UID#1, UID#2, ...]) or (NOAUTH, [])
    """

    reply = self._command("WATCHUIDS", timeout = timeout)

    while True:

      if re.search("^(NOAUTH|UIDS( +[0-9a-fA-F]+)*)$", reply):
        f = reply.upper().split()
        authorized = f[0] == "UIDS"
        yield (AUTHOK, f[1:]) if authorized else (NOAUTH, [])

      else:
        raise ValueError("unknown server reply '{}'".format(reply))

      if not authorized:
        break

      reply = self._command()



  def close(self):
    """Close the connection to the SiRFIDaL server
    """

    if self._sock is not None:
      self._sock.close()



  def __exit__(self, exc_type, exc_value, exc_traceback):
    """__exit__ method
    """

    self.close()



  def __del__(self):
    """__del__ method
    """

    self.close()
