#!/usr/bin/python3
"""This script is the cornerstone of the SiRFIDaL system: it runs as root in
the background and provides secure authentication services for local processes
wishing to authenticate a user against a RFID or NFC UID, or manipulate the
list UID <-> user associations without exposing the UIDs to the processes.

The script performs the following functions:

* Background functions
  - Handle reading RFID / NFC UIDs from different connected readers (several
    PC/SC readers and a single serial reader may be watched concurrently)
  - Internally maintain a list of of currently active UIDs - that is, the list
    of UIDs of RFID or NFC transponders currently readable by the readers at
    any given time
  - Manipulate the list of UID <-> user association file: read the encrypted
    UIDs file, match active UIDs against the encrypted UIDs, encrypt new UIDs
    and associate them with users, and write the file back.

* Server for local frontend programs to request one of the following services:
  - Authenticate a user against one of the currently active UIDs, waiting for
    up to a requested time for a successful authentication
  - Add an authenticate user - i.e. associate a user with a single currently
    active UID and save this association in the encrypted UIDs file
  - Delete an authenticated user - i.e. disassociate a user from a single
    currently active UID in the encrypted UIDs file
  - Delete all entries for a user in the encrypted UIDs file
  - Watch the evolution of the number of active UIDs in real-time: not an
    authentication-related function, but a way for requesting processes to
    watch the activity on the readers without exposing the active UIDs, and
    without having to give ordinary users permission to access the readers
    directly

Note that clients started by non-local users (for example logged in through
telnet or SSH) will be denied services by the server. This is on purpose: the
server authenticates users against UIDs read from local RFID or NFC readers.
It would make no sense for a remote user to request authentication, as they're
not physically there to present a tag to a reader. If we let remote users
access the authentication services, it means a bad guy over SSH could simply
try to log in repeatedly until the legit local user comes around and scans
their tag. So we simply don't allow remote users to access the server, to
remove that security loophole.

As a result, if you run an "exotic" remote login service, don't forget to add
its process name to the list of disallowed parent process names in the
parameters below.

list of server requests and responses:

Service:        Authenticate a user
Client sends:   WAITAUTH <user> <max wait (int or float) in s>
Server replies: AUTHOK
                NOAUTH

Service:        Watch the evolution of the number of active UIDs in real-time
Client sends:   WATCHNBUIDS
Server replies: NBUIDS <new nb of active UIDS> <change since previous update>

Service:        Add a user <-> UID association in the encrypted UIDs file
Client sends:   ADDUSER <user> <max wait (int or float) in s>
Server replies: TIMEOUT
                EXISTS
                WRITEERR
                OK

Service:        Delete a user <-> UID association in the encrypted UIDs file
Client sends:   DELUSER <user> <max wait (int or float) in s>
Server replies: TIMEOUT
                NONE
                WRITEERR
                OK

Service:        Delete all entries in encrypted UIDs file matching a user
Client sends:   DELUSER <user> -1
Server replies: NONE
                WRITEERR
                OK

After receiving a reply to a WAITAUTH, ADDUSER or DELUSER request, the client
is expected to close the socket within a certain grace period. The client may
lodge a new request within that grace period. If it doesn't, the server will
force-close the socket at the end of the grace period.

After receiving a WATCHNBUIDS request, the server continuously sends updates
on the number of active UIDs and never closes the socket. It's up to the client
to close its end of the socket to terminate the request. At any given time,
the client may lodge a new request, cancelling and replacing the running
WATCHNBUIDS request.

See the parameters below to configure this script.
"""

### Parameters
# Types of RFID / NFC readers to watch
watch_pcsc=True
watch_serial=True

# PC/SC parameters
pcsc_read_every=0.2 #s

# Serial parameters
serial_read_every=0.2 #s
serial_reader_dev_file="/dev/ttyACM0"
serial_uid_not_sent_inactive_timeout=1 #s

# Server parameters
max_server_connections=10
max_auth_request_wait=60 #s
client_force_close_socket_timeout=60 #s
socket_path="/tmp/sirfidal_server.socket"

# Encrypted UIDs file path
encrypted_uids_file="/etc/sirfidal_encr_uids"

# Names of disallowed parent process names for requesting processes
remote_user_parent_process_names=["sshd", "telnetd"]



### Modules
import os
import re
import sys
import pwd
import json
import crypt
import struct
import psutil
from time import sleep
from select import select
from datetime import datetime
from smartcard.scard import *
from signal import signal, SIGCHLD
from filelock import FileLock, Timeout
from multiprocessing import Process, Queue, Pipe
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_REUSEADDR, SO_PEERCRED



### Defines
MAIN_PROCESS_KEEPALIVE=0
PCSC_LISTENER_UIDS_UPDATE=1
SERIAL_LISTENER_UIDS_UPDATE=2
NEW_CLIENT=3
NEW_CLIENT_ACK=4
VOID_REQUEST=5
VOID_REQUEST_TIMEOUT=6
WAITAUTH_REQUEST=7
AUTH_RESULT=8
AUTH_OK=9
AUTH_NOK=10
WATCHNBUIDS_REQUEST=11
NBUIDS_UPDATE=12
ADDUSER_REQUEST=13
DELUSER_REQUEST=14
ENCRUIDS_UPDATE=15
ENCRUIDS_UPDATE_ERR_EXISTS=16
ENCRUIDS_UPDATE_ERR_NONE=17
ENCRUIDS_UPDATE_ERR_TIMEOUT=18
CLIENT_HANDLER_STOP_REQUEST=19
CLIENT_HANDLER_STOP=20



### Global variables
encruids_file_mtime=None
encruids=None



### Classes
class client:
  """Active client request
  """

  def __init__(self):

    self.uid=None
    self.gid=None
    self.main_out_p=None
    self.request=None
    self.user=None
    self.expires=None



### subroutines / subprocesses
def pcsc_listener(main_in_q):
  """Periodically read the UIDs from one or several PC/SC readers and send the
  list to the main process
  """

  # Wait for the status on the connected PC/SC readers to change and Get the
  # list of active PC/SC UIDs when it does
  readers_prev=None
  hcontext=None
  send_initial_update=True

  while True:

    uids=[]

    # Wait on a PC/SC card's status change
    readers=[]
  
    if not hcontext:
      r, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)

      if r!=SCARD_S_SUCCESS:
        del(hcontext)
        hcontext=None
  
    if hcontext:
      _, readers = SCardListReaders(hcontext, [])

      if not readers:
        SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext=None

    if readers and readers_prev!=readers:

      rs=[]
      readers_prev=readers
      for i in range(len(readers)):
        rs+=[(readers[i], SCARD_STATE_UNAWARE)]

      try:
        _, rs = SCardGetStatusChange(hcontext, 0, rs)
      except KeyboardInterrupt:
        return(-1)
      except:
        SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext=None
        readers=[]

    if readers:

      try:
        rv, rs = SCardGetStatusChange(hcontext, int(pcsc_read_every*1000), rs)
      except KeyboardInterrupt:
        return(-1)
      except:
        SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext=None
        readers=[]

    if not readers:
      sleep(pcsc_read_every)
      continue

    # Send a keepalive message to the main process so it can trigger timeouts
    main_in_q.put([MAIN_PROCESS_KEEPALIVE])

    # If a card's status has changed, re-read all the UIDs
    if rv==SCARD_S_SUCCESS or send_initial_update:

      for reader in readers:

        try:
          hresult, hcard, dwActiveProtocol = SCardConnect(
		  hcontext,
		  reader,
		  SCARD_SHARE_SHARED,
		  SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
		)

          hresult, response = SCardTransmit(
		  hcard,
		  dwActiveProtocol,
		  [0xFF,0xCA,0x00,0x00,0x00]
		)
          uids.append(":".join("{:02X}".format(b) for b in response))
        except KeyboardInterrupt:
          return(-1)
        except:
          pass

      # Send the list to the main process
      main_in_q.put([PCSC_LISTENER_UIDS_UPDATE, uids])

      send_initial_update=False



def serial_listener(main_in_q):
  """Periodically read the UIDs from a single serial reader and send the list
  to the main process. The reader must be a repeating reader - i.e. one that
  sends the UIDs of the active transponders repeatedly as long as they're
  readable, not just once when they're first read.
  """

  fdevfile=None
  uid_lastseens={}
  send_active_uids_update=True

  while True:

    uid=None

    # Open the reader's device file if it's closed
    if not fdevfile:
      try:
        fdevfile=open(serial_reader_dev_file, "r")
      except KeyboardInterrupt:
        return(-1)
      except:
        fdevfile=None
        sleep(2)	# Wait a bit as the device file is probably unavailable

    # Read a UID from the reader
    if fdevfile:
      try:
        if(select([fdevfile], [], [], serial_read_every)[0]):
          uid=fdevfile.readline().strip("\r\n")
        else:
          uid=None
      except KeyboardInterrupt:
        return(-1)
      except:
        uid=None

    # Close the device file in case of select timeout or read error, so we don't
    # block the file at any time if the readers gets disconnected, and it gets
    # properly reassigned by udev upon reconnecting. Also, wait a bit just in
    # case, to prevent any chance of running a tight loop and wasting CPU.
    if fdevfile and not uid:
      fdevfile.close()
      fdevfile=None
      sleep(serial_read_every)

    tstamp=int(datetime.now().timestamp())

    # If we got a UID, add or update its timestamp in the last-seen list
    if uid:
      if uid not in uid_lastseens:
        send_active_uids_update=True
      uid_lastseens[uid]=tstamp

    # Remove UID timestamps that are too old from the last-seen list
    for uid in list(uid_lastseens):
      if tstamp - uid_lastseens[uid] > serial_uid_not_sent_inactive_timeout:
        del uid_lastseens[uid]
        send_active_uids_update=True

    # If the active UIDs have changed...
    if send_active_uids_update:

      # ...end the list to the main process...
      main_in_q.put([SERIAL_LISTENER_UIDS_UPDATE, list(uid_lastseens)])
      send_active_uids_update=False

    else:

      # ...else send a keepalive message to the main process so it can trigger
      # timeouts
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])



def server(main_in_q, sock):
  """Handle client connections to the server
  """

  # SIGCHLD handler to reap defunct client handlers when they exit
  def sigchld_handler(sig, fname):
    os.wait()

  # Run the server
  signal(SIGCHLD, sigchld_handler)

  while True:

    # Wait for a connection
    conn, _ = sock.accept()

    # Get the calling process' PID, UID and GID
    creds=conn.getsockopt(SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)

    # If the user isn't local, close the connection
    if is_remote_user(pid):
      conn.close()
      continue

    # Create a pipe for the main process to send messages to the client handler
    main_out_p, chandler_out_p = Pipe()

    # Spawn a client handler
    Process(target=client_handler, args=(
		  uid,
		  gid,
		  main_in_q,
		  main_out_p,
		  chandler_out_p,
		  conn
		)).start()
    


def client_handler(uid, gid, main_in_q, main_out_p, chandler_out_p, conn):
  """Handler communications between the client and the main process
  """

  # Drop our privileges to that of the client, so we can't write to the
  # encrypted file if the calling process can't either. Also set umask so
  # that if we have to create the file as root, root will be able to read and
  # write to it, users belonging to the right group will only be able to write
  # (to add or delete UIDs without being able to read the encrypted file) and
  # others may not access it in any way.
  try:
    os.setgroups(os.getgrouplist(pwd.getpwuid(uid).pw_name, gid))
    os.setgid(gid)
    os.setuid(uid)
    os.umask(0o057)
  except:
    return(0)

  # Client receive buffer
  crecvbuf=""

  # Client send buffer
  csendbuf=""

  pid=os.getpid()

  force_stop_tstamp=None

  # Inform the main process that we have a new client
  main_in_q.put([NEW_CLIENT, [pid, main_out_p]])
  new_client_ack=False 

  while True:

    # Do we have something to send to the client?
    if(csendbuf):
      try:
        conn.sendall((csendbuf + "\n").encode("ascii"))
      except:	# oops, the socket was closed
        # inform the main process we want to stop and close the socket.
        main_in_q.put([client_handler_stop_request, [pid, main_out_p]])
        conn.close()
        conn=none
      csendbuf=""

    # Wait for either the main process of the client to send us something
    fds=select(
	  [chandler_out_p] + ([conn] if conn and new_client_ack else []), \
	  [], [], 1
	)[0]

    # Did we hit the timeout?
    if not fds:

      # Should we force-close the socket and quit?
      if force_stop_tstamp and datetime.now().timestamp() > force_stop_tstamp:

        main_in_q.put([CLIENT_HANDLER_STOP_REQUEST, [pid, main_out_p]])
        conn.close()
        conn=None
        continue

    for fd in fds:

      # Message from the main process
      if fd==chandler_out_p:

        msg=fd.recv()

        # New client notification aknowledgment
        if msg[0]==NEW_CLIENT_ACK:
          new_client_ack=True
          continue

        # The main process reports an authentication result: send the result
        # to the client
        elif msg[0]==AUTH_RESULT:
          csendbuf="AUTHOK" if msg[1][0]==AUTH_OK else "NOAUTH"
          continue

        # The main process reports an update in the number of active UIDs: sent
        # it to the client
        elif msg[0]==NBUIDS_UPDATE:
          csendbuf="NBUIDS {} {}".format(msg[1][0], msg[1][1])
          continue

        # The main process reports a timeout waiting for a UID to associate
        # or disassociate with a UID
        elif msg[0]==ENCRUIDS_UPDATE_ERR_TIMEOUT:
          csendbuf="TIMEOUT"
          continue

        # The main process reports an error updating the encryption UIDs
        # because the user <-> UID association already exists: notify the client
        elif msg[0]==ENCRUIDS_UPDATE_ERR_EXISTS:
          csendbuf="EXISTS"
          continue

        # The main process reports an error updating the encryption UIDs
        # because it hasn't found any user <-> UID association to delete:
        # notify the client
        elif msg[0]==ENCRUIDS_UPDATE_ERR_NONE:
          csendbuf="NONE"
          continue

        # The main process wants us to update the encryption UIDs file
        elif msg[0]==ENCRUIDS_UPDATE:
          csendbuf="OK" if write_encruids(msg[1]) else "WRITEERR"
          continue

        # The main process reports a void request timeout (in other words, the
        # client has failed to place a valid request in time).
        elif msg[0]==VOID_REQUEST_TIMEOUT:

          # Inform the main process we want to stop and close the socket.
          main_in_q.put([CLIENT_HANDLER_STOP_REQUEST, [pid, main_out_p]])
          conn.close()
          conn=None

          continue

        # The main process instructs us to stop
        elif msg[0]==CLIENT_HANDLER_STOP:
          return(0)

      # Message from the client
      elif fd==conn:

        # Get data from the socket
        b=fd.recv(256).decode("ascii")

        # If we got nothing, the client has closed its end of the socket.
        # Inform the main process we want to stop and close the socket.
        if len(b)==0:
          main_in_q.put([CLIENT_HANDLER_STOP_REQUEST, [pid, main_out_p]])
          conn.close()
          conn=None
          continue

        # Split the data into lines
        clines=[]
        for c in b:

          if c=="\n" or c=="\r":
            clines.append(crecvbuf)
            crecvbuf=""

          elif len(crecvbuf)<256 and c.isprintable():
            crecvbuf+=c
 
        # Process client requests
        for l in clines:

          # WAITAUTH request
          m=re.findall("^WAITAUTH\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
          if m:
            main_in_q.put([WAITAUTH_REQUEST, [pid, m[0][0], float(m[0][1])]])

          # WATCHNBUIDS request
          m=re.findall("^WATCHNBUIDS$", l)
          if m:
            main_in_q.put([WATCHNBUIDS_REQUEST, [pid]])

          # ADDUSER request
          m=re.findall("^ADDUSER\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
          if m:
            main_in_q.put([ADDUSER_REQUEST, [pid, m[0][0], float(m[0][1])]])

          # DELUSER request
          m=re.findall("^DELUSER\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
          if m:
            main_in_q.put([DELUSER_REQUEST, [pid, m[0][0], float(m[0][1])]])



def is_remote_user(pid):
  """Attempt to determine if the user is logged in locally (linux console,
  X terminal...) or remotely by tracing the parent processes and trying to
  find telltale process names
  """
  pprocess=psutil.Process(pid=pid)

  while(pprocess and pprocess.name() not in remote_user_parent_process_names):
    pprocess=pprocess.parent()

  return(pprocess!=None)



def load_encruids():
  """Read and verify the content of the encrypted UIDs file. Return a list of
  lists of username -> encrypted UID, or None in case of a read or format error.
  """

  global encruids_file_mtime
  global encruids

  # Get the file's modification time
  try:
    mt=os.stat(encrypted_uids_file).st_mtime
  except:
    return(None)

  # Has the file changed?
  if not encruids_file_mtime:
    encruids_file_mtime=mt
  else:
    if mt <= encruids_file_mtime:
      return(encruids)

  encruids_file_mtime=mt

  # Re-read the file
  try:
    with open(encrypted_uids_file, "r") as f:
      new_encruids=json.load(f)
  except:
    return(encruids)

  # Validate the structure of the JSON format
  if not isinstance(new_encruids, list):
    return(encruids)

  for entry in new_encruids:
    if not (
	  isinstance(entry, list) and
	  isinstance(entry[0], str) and
	  isinstance(entry[0], str)
	):
      return(encruids)

  # Update the encrypted UIDs currently in memory
  encruids=new_encruids
  return(encruids)



def write_encruids(new_encruids):
  """Save a new set of encrypted UIDs
  """

  try:
    with open(encrypted_uids_file, "w") as f:
      json.dump(new_encruids, f, indent=2)
  except:
    return(False)

  return(True)



### Main routine
def main():
  """Main routine
  """

  # Main routine's input queue
  main_in_q=Queue()

  # Set up the server's socket
  sock=socket(AF_UNIX, SOCK_STREAM)

  socklock=FileLock(socket_path + ".lock")
  try:
    with socklock.acquire(timeout=1):
      os.unlink(socket_path)
  except Timeout:
    print("Error: socket locked. Giving up.")
    return(-1)
  except:
    pass
  finally:
    socklock.release()
  sock.bind(socket_path)

  os.chmod(socket_path, 0o666)

  sock.listen(max_server_connections)

  # Start the server
  Process(target=server, args=(main_in_q, sock,)).start()

  # Start the PC/SC listener
  if watch_pcsc:
    Process(target=pcsc_listener, args=(main_in_q,)).start()

  # Start the serial listener
  if watch_serial:
    Process(target=serial_listener, args=(main_in_q,)).start()
  


  # Main process
  active_pcsc_uids=[]
  active_serial_uids=[]
  active_uids=[]
  active_uids_prev=None
  send_active_uids_update=False
  active_clients={}

  while True:
    
    # Get a message from another process
    msg=main_in_q.get()
    msg_tstamp=datetime.now().timestamp()

    # Skip all tests for other kinds of messages if it's a keepalive message
    if msg[0] != MAIN_PROCESS_KEEPALIVE:

      # The message is an update of the active UIDs from the PC/SC listener
      if msg[0] == PCSC_LISTENER_UIDS_UPDATE:

        active_pcsc_uids=msg[1]
        active_uids_prev=active_uids
        active_uids=active_pcsc_uids + active_serial_uids
        send_active_uids_update=True

      # The message is an update of the active UIDs from the serial listener
      elif msg[0] == SERIAL_LISTENER_UIDS_UPDATE:

        active_serial_uids=msg[1]
        active_uids_prev=active_uids
        active_uids=active_pcsc_uids + active_serial_uids
        send_active_uids_update=True

      # New client notification from a client handler
      elif msg[0] == NEW_CLIENT:

        # Create this client in the list of active clients and assign it the
        # void request to time out the client if it stays idle too long
        active_clients[msg[1][0]]=client()
        active_clients[msg[1][0]].main_out_p=msg[1][1]
        active_clients[msg[1][0]].request=VOID_REQUEST
        active_clients[msg[1][0]].expires=msg_tstamp + \
			client_force_close_socket_timeout
        msg[1][1].send([NEW_CLIENT_ACK])

      # The client requested that we either:
      # - authenticate a user within a certain delay (capped)
      # - associate a user with a UID and add it to the encrypted UIDs file,
      #   waiting for the new UID within a certain delay (capped)
      # - disassociate a user from a UID, waiting for the UID within a certain
      #   deiay (capped) or remove all entries for the user in the encrypted
      #   UIDs file (delay < 0)
      elif msg[0] == WAITAUTH_REQUEST or \
		msg[0] == ADDUSER_REQUEST or \
		msg[0] == DELUSER_REQUEST:

        # Update this client's request in the list of active requests. Cap the
        # delay the client may request
        active_clients[msg[1][0]].request=msg[0]
        active_clients[msg[1][0]].user=msg[1][1]
        active_clients[msg[1][0]].expires=None if msg[1][2] < 0 else \
		msg_tstamp + (msg[1][2] if msg[1][2] <= max_auth_request_wait \
		else max_auth_request_wait)

      # The client requested to watch the evolution of the number of active
      # UIDs in real time
      elif msg[0] == WATCHNBUIDS_REQUEST:

        # Update this client's request in the list of active requests.
        # No timeout for this request: it's up to the client to close the
        # socket when it's done
        active_clients[msg[1][0]].request=WATCHNBUIDS_REQUEST
        active_clients[msg[1][0]].user=None
        active_clients[msg[1][0]].expires=None

      # Remove a client from the list of active clients and tell the handler
      # to stop
      elif msg[0] == CLIENT_HANDLER_STOP_REQUEST:

        del(active_clients[msg[1][0]])
        msg[1][1].send([CLIENT_HANDLER_STOP])



    # Process the active clients' requests
    for cpid in list(active_clients):

      auth=False

      # If we arrive here following a keepalive message, only process timeouts
      if msg[0] != MAIN_PROCESS_KEEPALIVE:

        # Request to watch the evolution of the number of active UIDs in
        # real-time: send an update if one is available
        if send_active_uids_update and \
		active_clients[cpid].request == WATCHNBUIDS_REQUEST and \
		active_uids_prev != None and \
		 len(active_uids) != len(active_uids_prev):
          active_clients[cpid].main_out_p.send([NBUIDS_UPDATE, \
		[len(active_uids), len(active_uids) - len(active_uids_prev)]])

        # Authentication request: reload the encrypted UIDs file if needed
        elif active_clients[cpid].request == WAITAUTH_REQUEST and \
		load_encruids():

          # Try to match one of the active UIDs with one of the registered
          # encrypted UIDs associated with that user
          for uid in active_uids:
 
            for registered_user, registered_uid_encr in encruids:
              if registered_user == active_clients[cpid].user and crypt.crypt(
			  uid,
			  registered_uid_encr
			) == registered_uid_encr:
                auth=True	# User authenticated

        # Add user request: if we have exactly one active UID, associate it
        # with the requested user
        elif active_clients[cpid].request == ADDUSER_REQUEST and \
		len(active_uids)==1:

          # Load the current encrypted UIDs file
          new_encruids=load_encruids()
          if new_encruids==None:
            new_encruids=[]

          # Don't replace an existing user <-> UID association: if we find one,
          # notify the client handler and replace the request with a fresh void
          # request and associated timeout
          for registered_user, registered_uid_encr in new_encruids:
            if registered_user == active_clients[cpid].user and crypt.crypt(
			  active_uids[0],
			  registered_uid_encr
			) == registered_uid_encr:
              active_clients[cpid].main_out_p.send([ENCRUIDS_UPDATE_ERR_EXISTS])
              active_clients[cpid].request=VOID_REQUEST
              active_clients[cpid].expires=msg_tstamp + \
			client_force_close_socket_timeout
              break;

          # Encrypt and associate the UID with the user, send the updated
          # encrypted UIDs to the client handler and replace the request with a
          # fresh void request and associated timeout
          if active_clients[cpid].request!=VOID_REQUEST:

            new_encruids.append([
		  active_clients[cpid].user,
		  crypt.crypt(active_uids[0], crypt.mksalt())
		])
            active_clients[cpid].main_out_p.send([ENCRUIDS_UPDATE,
		new_encruids])
            active_clients[cpid].request=VOID_REQUEST
            active_clients[cpid].expires=msg_tstamp + \
			client_force_close_socket_timeout

        # Delete user request: if we have exactly one active UID, disassociate
        # any matching user <-> UID - unless we have no timeout, in which case
        # remove all user <-> UID associations matching the requested user
        elif active_clients[cpid].request == DELUSER_REQUEST and \
		(active_clients[cpid].expires == None or len(active_uids)==1):

          # Load the current encrypted UIDs file
          curr_encruids=load_encruids()
          if curr_encruids==None:
            curr_encruids=[]

          # Find one or more existing user <-> UID associations and remove
          # them if needed
          assoc_deleted=False
          new_encruids=[]
          for registered_user, registered_uid_encr in curr_encruids:
            if registered_user == active_clients[cpid].user and (
			active_clients[cpid].expires == None or crypt.crypt(
			  active_uids[0],
			  registered_uid_encr
			) == registered_uid_encr):
              assoc_deleted=True
            else:
              new_encruids.append([registered_user, registered_uid_encr])

          # If we found one or more associations to delete, send the updated
          # encrypted UIDs to the client handler. Otherwise notify the client.
          # Then replace the request with a fresh void request and associated
          # timeout
          if assoc_deleted:
            active_clients[cpid].main_out_p.send([ENCRUIDS_UPDATE,
		new_encruids])
          else:
            active_clients[cpid].main_out_p.send([ENCRUIDS_UPDATE_ERR_NONE])

          active_clients[cpid].request=VOID_REQUEST
          active_clients[cpid].expires=msg_tstamp + \
			client_force_close_socket_timeout

          

      # If an authentication request has timed out or the authentication is
      # successful, notify the client handler and replace the request with
      # a fresh void request and associated timeout
      if active_clients[cpid].request == WAITAUTH_REQUEST and \
		(auth or active_clients[cpid].expires==None or \
		msg_tstamp >= active_clients[cpid].expires):
        active_clients[cpid].main_out_p.send([AUTH_RESULT,
		[AUTH_OK if auth else AUTH_NOK]])
        active_clients[cpid].request=VOID_REQUEST
        active_clients[cpid].expires=msg_tstamp + \
			client_force_close_socket_timeout

      # If an add user or del user request has timed out, notify the client
      # handler and replace the request with a fresh void request and
      # associated timeout
      if (active_clients[cpid].request == ADDUSER_REQUEST or \
		active_clients[cpid].request == DELUSER_REQUEST) and \
		(active_clients[cpid].expires==None or \
		msg_tstamp >= active_clients[cpid].expires):
        active_clients[cpid].main_out_p.send([ENCRUIDS_UPDATE_ERR_TIMEOUT])
        active_clients[cpid].request=VOID_REQUEST
        active_clients[cpid].expires=msg_tstamp + \
			client_force_close_socket_timeout

      # if a void request request has timed out, notify the client handler
      # and clear the request
      elif active_clients[cpid].request == VOID_REQUEST and \
		msg_tstamp >= active_clients[cpid].expires:
        active_clients[cpid].main_out_p.send([VOID_REQUEST_TIMEOUT])
        active_clients[cpid].request=None

    # Prevent duplicate active UIDs updates being sent to watcher clients
    if msg[0] != MAIN_PROCESS_KEEPALIVE:
      send_active_uids_update=False

      

### Jump to the main routine
if __name__ == "__main__":
  sys.exit(main())
