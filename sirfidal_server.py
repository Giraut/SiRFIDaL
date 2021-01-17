#!/usr/bin/python3
"""This script is the cornerstone of the SiRFIDaL system: it runs as root in
the background and provides secure authentication services for local processes
wishing to authenticate a user against a RFID or NFC UID, or manipulate the
list UID <-> user associations without exposing the UIDs to the processes.

The script performs the following functions:

* Background functions

  - Handle reading RFID / NFC UIDs from different connected readers: several
    PC/SC readers, a single serial reader, a single HID reader, an Android
    device used as an external NFC reader, a Proxmark3 reader, a
    Chameleon Mini / Tiny, a uFR / uFR Nano Online in slave mode
    may be watched concurrently

  - Internally maintain a list of of currently active UIDs - that is, the list
    of UIDs of RFID or NFC transponders currently readable by the readers at
    any given time

  - Manipulate the list of UID <-> user association file: read the encrypted
    UIDs file, match active UIDs against the encrypted UIDs, encrypt new UIDs
    and associate them with users, and write the file back.

* Server for local frontend programs to request one of the following services:

  - Authenticate a user against one of the currently active UIDs, waiting for
    up to a requested time for a successful authentication

  - Add an authenticated user - i.e. associate a user with a single currently
    active UID and save this association in the encrypted UIDs file

  - Delete an authenticated user - i.e. disassociate a user from a single
    currently active UID in the encrypted UIDs file

  - Delete all entries for a user in the encrypted UIDs file

  - Watch the evolution of the number of active UIDs in real-time: not an
    authentication-related function, but a way for requesting processes to
    watch the activity on the readers without exposing the active UIDs, and
    without having to give ordinary users permission to access the readers
    directly

  - Watch the evolution of the actual list of active UIDs in real-time: not an
    authentication-related function, but a way for requesting processes to
    get the actual UIDs read on the readers, currently active in the server.
    For security reasons, the server will only honor this request for client
    processes run by root

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
Server replies: AUTHOK [authenticating UID]
                NOAUTH

Service:        Watch the evolution of the number of active UIDs in real-time
Client sends:   WATCHNBUIDS
Server replies: NBUIDS <new nb of active UIDS> <change since previous update>

Service:        Watch the evolution of the list of active UIDs in real-time
Client sends:   WATCHUIDS
Server replies: UIDS [active UID #1] [active UID #2] [active UID #3] ...
                NOAUTH

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

After a successful WAITAUTH request, if the requesting process owner is the
the same as the user they request an authentication for (i.e. the user
authenticates themselves), the server returns the authenticating UID in
plaintext after the AUTHOK reply, to use for whatever purpose they see fit
(encryption usually). If the requesting process owner requests authentication
for another user (e.g. su), the UID isn't sent after AUTHOK.

After receiving a reply to a WAITAUTH, ADDUSER or DELUSER request, the client
is expected to close the socket within a certain grace period. The client may
lodge a new request within that grace period. If it doesn't, the server will
force-close the socket at the end of the grace period.

After receiving a WATCHNBUIDS or WATCHUIDS request, the server continuously
sends updates and never closes the socket. It's up to the client to close its
end of the socket to terminate the request. At any given time, the client may
lodge a new request, canceling and replacing the running WATCHNBUIDS or
WATCHUIDS request.

See the parameters below to configure this script.
"""

### Parameters
# Types of RFID / NFC readers to watch
watch_pcsc      =True
watch_serial    =False
watch_hid       =False
watch_adb       =False	#Android device used as an external NFC reader
watch_pm3       =False	#Proxmark3 reader used as a "dumb" UID reader
watch_chameleon =False	#Chameleon Mini / Tiny used as an external NFC reader
watch_ufr       =False	#uFR or uFR Nano Online reader in slave mode

# PC/SC parameters
pcsc_read_every=0.2 #s

# Serial parameters
serial_read_every=0.2 #s
serial_reader_dev_file="/dev/ttyUSB0"
serial_baudrate=9600
serial_uid_not_sent_inactive_timeout=1 #s

# HID parameters
hid_read_every=0.2 #s
hid_reader_dev_file="/dev/input/by-id/"	\
			"usb-ACS_ACR1281_Dual_Reader-if01-event-kbd"
hid_simulate_uid_stays_active=1 #s

# ADB parameters
adb_read_every=0.2 #s
adb_client="/usr/bin/adb"
adb_nfcuid_log_prefix="nfcuid:"
adb_persistent_mode=True
adb_uid_timeout_in_non_persistent_mode=1 #s

# Proxmark3 parameters
pm3_read_every=0.2 #s
pm3_reader_dev_file="/dev/ttyACM0"
pm3_client="/usr/local/bin/proxmark3"
pm3_client_workdir="/tmp"
pm3_client_comm_timeout=2 #s
pm3_read_iso14443a =True
pm3_read_iso15693  =False
pm3_read_em410x    =False
pm3_read_indala    =False
pm3_read_fdx       =False

# Chameleon Mini / Tiny parameters
chameleon_read_every=0.2 #s
chameleon_dev_file="/dev/ttyACM0"
chameleon_iso14443a_reader_slot=8
chameleon_client_comm_timeout=2 #s
chameleon_uid_not_sent_inactive_timeout=1 #s

# uFR or uFR Nano Online in slave mode
ufr_read_every=0.5 #s
ufr_device="tcp://ufr:8881"
ufr_polled_mode=False		# Polled or asynchronous ID sending mode
ufr_polled_power_saving=False	# uFR firmware > v5.0.51 required
ufr_debounce_delay=0.2 #s
ufr_no_rgb1=(24, 16, 0)		# For Nano Online, LED1 color
ufr_no_rgb2_card_off=(16, 0, 0)	# For Nano Online, LED2 color if no card present
ufr_no_rgb2_card_on=(0, 16, 0)	# For Nano Online, LED2 color if card present
ufr_device_check_every=10 #s

# Server parameters
max_server_connections=10
max_auth_request_wait=60 #s
client_force_close_socket_timeout=60 #s
socket_path="/tmp/sirfidal_server.socket"

# Encrypted UIDs file path
encrypted_uids_file="/etc/sirfidal_encr_uids"

# Names of disallowed parent process names for requesting processes. This is a
# very weak security check, but we leave it there just in case
remote_user_parent_process_names=["sshd", "telnetd"]



### Modules
import os
import re
import sys
import pwd
import json
import struct
import psutil
from time import sleep
from pty import openpty
from select import select
from string import hexdigits
from datetime import datetime
from crypt import crypt, mksalt
from signal import signal, SIGCHLD
from setproctitle import setproctitle
from filelock import FileLock, Timeout
from subprocess import Popen, DEVNULL, PIPE
from multiprocessing import Process, Queue, Pipe
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
		SO_REUSEADDR, SO_PEERCRED



### Defines
MAIN_PROCESS_KEEPALIVE         =0
PCSC_LISTENER_UIDS_UPDATE      =1
SERIAL_LISTENER_UIDS_UPDATE    =2
HID_LISTENER_UIDS_UPDATE       =3
ADB_LISTENER_UIDS_UPDATE       =4
PM3_LISTENER_UIDS_UPDATE       =5
CHAMELEON_LISTENER_UIDS_UPDATE =6
UFR_LISTENER_UIDS_UPDATE       =7
NEW_CLIENT                     =8
NEW_CLIENT_ACK                 =9
VOID_REQUEST                   =10
VOID_REQUEST_TIMEOUT           =11
WAITAUTH_REQUEST               =12
AUTH_RESULT                    =13
AUTH_OK                        =14
AUTH_NOK                       =15
WATCHNBUIDS_REQUEST            =16
NBUIDS_UPDATE                  =17
WATCHUIDS_REQUEST              =18
UIDS_UPDATE                    =19
ADDUSER_REQUEST                =20
DELUSER_REQUEST                =21
ENCRUIDS_UPDATE                =22
ENCRUIDS_UPDATE_ERR_EXISTS     =23
ENCRUIDS_UPDATE_ERR_NONE       =24
ENCRUIDS_UPDATE_ERR_TIMEOUT    =25
CLIENT_HANDLER_STOP_REQUEST    =26
CLIENT_HANDLER_STOP            =27



### Global variables
encruids_file_mtime=None
encruids=[]



### Classes
class client:
  """Active client request
  """

  def __init__(self):

    self.pw_name=None
    self.main_out_p=None
    self.request=None
    self.user=None
    self.expires=None
    self.new_request=True



### subroutines / subprocesses
def pcsc_listener(main_in_q):
  """Periodically read the UIDs from one or several PC/SC readers and send the
  list of active UIDs to the main process
  """

  # Modules
  import smartcard.scard as sc

  setproctitle("sirfidal_server_pcsc_listener")

  # Wait for the status on the connected PC/SC readers to change and Get the
  # list of active PC/SC UIDs when it does
  readers_prev=None
  hcontext=None
  send_initial_update=True

  while True:

    active_uids=[]

    # Wait on a PC/SC card's status change
    readers=[]

    if not hcontext:
      r, hcontext = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)

      if r!=sc.SCARD_S_SUCCESS:
        del(hcontext)
        hcontext=None

    if hcontext:
      _, readers = sc.SCardListReaders(hcontext, [])

      if not readers:
        sc.SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext=None

    if readers and readers_prev!=readers:

      rs=[]
      readers_prev=readers
      for i in range(len(readers)):
        rs+=[(readers[i], sc.SCARD_STATE_UNAWARE)]

      try:
        _, rs = sc.SCardGetStatusChange(hcontext, 0, rs)
      except KeyboardInterrupt:
        return(-1)
      except:
        sc.SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext=None
        readers=[]

    if readers:

      try:
        rv, rs = sc.SCardGetStatusChange(hcontext, int(pcsc_read_every * 1000),
					 rs)
      except KeyboardInterrupt:
        return(-1)
      except:
        sc.SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext=None
        readers=[]

    if not readers:
      sleep(pcsc_read_every)
      continue

    # Send a keepalive message to the main process so it can trigger timeouts
    main_in_q.put([MAIN_PROCESS_KEEPALIVE])

    # If a card's status has changed, re-read all the UIDs
    if rv==sc.SCARD_S_SUCCESS or send_initial_update:

      for reader in readers:

        try:

          hresult, hcard, dwActiveProtocol = sc.SCardConnect(
		  hcontext,
		  reader,
		  sc.SCARD_SHARE_SHARED,
		  sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1
		)
          hresult, response = sc.SCardTransmit(
		  hcard,
		  dwActiveProtocol,
		  [0xFF, 0xCA, 0x00, 0x00, 0x00]
		)

          uid="".join("{:02X}".format(b) for b in response)

          if uid[-4:]=="9000":
            uid=uid[:-4]

          if uid:
            active_uids.append(uid)

        except KeyboardInterrupt:
          return(-1)
        except:
          pass

      # Send the list to the main process
      main_in_q.put([PCSC_LISTENER_UIDS_UPDATE, active_uids])

      send_initial_update=False



def serial_listener(main_in_q):
  """Periodically read the UIDs from a single serial reader and send the list
  of active UIDs to the main process. The reader must be a repeating reader -
  i.e. one that sends the UIDs of the active transponders repeatedly as long as
  they're readable, not just once when they're first read.
  """

  # Modules
  from serial import Serial

  setproctitle("sirfidal_server_serial_listener")

  recvbuf=""

  uid_lastseens={}

  serdev=None
  send_active_uids_update=True

  while True:

    # Open the reader's device file if it's closed
    if not serdev:
      try:
        serdev=Serial(serial_reader_dev_file, serial_baudrate, timeout=0)
      except KeyboardInterrupt:
        return(-1)
      except:
        serdev=None

    if not serdev:
      sleep(2)	# Wait a bit to reopen the device
      continue

    # Read UIDs from the reader
    rlines=[]
    b=""
    try:

      if(select([serdev.fileno()], [], [], serial_read_every)[0]):

        try:

          b=os.read(serdev.fileno(), 256).decode("ascii")

        except KeyboardInterrupt:
          return(-1)
        except:
          b=""

        if not b:
          try:
            serdev.close()
          except:
            pass
          serdev=None
          sleep(2)	# Wait a bit to reopen the device
          continue


        # Split the data into lines
        for c in b:

          if c=="\n" or c=="\r":
            rlines.append(recvbuf)
            recvbuf=""

          elif len(recvbuf)<256 and c.isprintable():
            recvbuf+=c

    except KeyboardInterrupt:
      return(-1)
    except:
      try:
        serdev.close()
      except:
        pass
      serdev=None
      sleep(2)	# Wait a bit to reopen the device
      continue

    tstamp=int(datetime.now().timestamp())

    # Process the lines from the device
    for l in rlines:

      # Strip anything not hexadecimal out of the UID and uppercase it,
      # so it has a chance to be compatible with UIDs read by the other
      # listeners
      uid="".join([c for c in l.upper() if c in hexdigits])

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

      # ...send the list to the main process...
      main_in_q.put([SERIAL_LISTENER_UIDS_UPDATE, list(uid_lastseens)])
      send_active_uids_update=False

    else:

      # ...else send a keepalive message to the main process so it can trigger
      # timeouts
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])



def hid_listener(main_in_q):
  """Read UIDs from a single HID reader (aka a "keyboard wedge") and send the
  list of active UIDs to the main process.

  Sadly, almost all keyboard wedges are one-shot and not repeating readers,
  i.e. they only send the UID once upon scanning. This routine simulates the
  presence of a transponder in the list of active UIDs for a certain period of
  time, then simulates its getting inactive. There is no way to assess the
  presence of a transponder on those readers, so that's the best we can do.
  However, that means client applications that depend on being able to assess
  continued authentication of a UID will not work correctly.
  """

  # Modules
  from evdev import InputDevice, categorize, ecodes

  setproctitle("sirfidal_server_hid_listener")

  active_uid_expires={}

  SC_LSHIFT=42
  SC_RSHIFT=54
  SC_ENTER=28
  KEYUP=0
  KEYDOWN=1

  scancodes_us_kbd={
      2: ["1", "!"],  3: ["2", "@"],  4: ["3", "#"],  5: ["4", "$"],
      6: ["5", "%"],  7: ["6", "^"],  8: ["7", "&"],  9: ["8", "*"],
     10: ["9", "("], 11: ["0", ")"], 12: ["-", "_"], 13: ["=", "+"],
     16: ["q", "Q"], 17: ["w", "W"], 18: ["e", "E"], 19: ["r", "R"],
     20: ["t", "T"], 21: ["y", "Y"], 22: ["u", "U"], 23: ["i", "I"],
     24: ["o", "O"], 25: ["p", "P"], 26: ["[", "{"], 27: ["]", "}"],
     30: ["a", "A"], 31: ["s", "S"], 32: ["d", "D"], 33: ["f", "F"],
     34: ["g", "G"], 35: ["h", "H"], 36: ["j", "J"], 37: ["k", "K"],
     38: ["l", "L"], 39: [";", ":"], 40: ["'", '"'], 41: ["`", "~"],
     43: ["\\","|"], 44: ["z", "Z"], 45: ["x", "X"], 46: ["c", "C"],
     47: ["v", "V"], 48: ["b", "B"], 49: ["n", "N"], 50: ["m", "M"],
     51: [",", "<"], 52: [".", ">"], 53: ["/", "?"], 57: [" ", " "],
  }

  recvbuf=""

  shifted=0

  hiddev=None
  send_active_uids_update=True

  while True:

    # Grab the HID device for exclusive use by us
    if not hiddev:

      try:
        hiddev=InputDevice(hid_reader_dev_file)
        hiddev.grab()
      except:
        if hiddev:
          hiddev.close()
        hiddev=None
        sleep(2)	# Wait a bit as the device file is probably unavailable
        continue

    rlines=[]

    # Wait for scancodes from the HID reader, or timeout
    fds = select([hiddev.fd], [], [], hid_read_every)[0]

    now=datetime.now().timestamp()

    # read scancodes
    if fds:

      try:
        events=list(hiddev.read())
      except:
        if hiddev:
          hiddev.close()
        hiddev=None
        sleep(2)	# Wait a bit as the device file is probably unavailable
        continue

      for event in events:

        if event.type == ecodes.EV_KEY:

          d = categorize(event)

          if d.scancode == SC_LSHIFT or d.scancode == SC_RSHIFT:

            if d.keystate == KEYDOWN or d.keystate == KEYUP:
              shifted=1 if d.keystate == KEYDOWN else 0

          elif d.scancode == SC_ENTER:

            if recvbuf:

              rlines.append(recvbuf)
              recvbuf=""

          elif d.keystate == KEYDOWN and len(recvbuf) < 256:
              recvbuf += scancodes_us_kbd.get(d.scancode, ["", ""])[shifted]

      # Process the lines from the HID reader
      for uid in rlines:

        # Strip anything not hexadecimal out of the UID and uppercase it,
        # so it has a chance to be compatible with UIDs read by the other
        # listeners
        uid="".join([c for c in uid.upper() if c in hexdigits])

        # Add or update UIDs in the expires table
        if uid not in active_uid_expires:
          send_active_uids_update=True

        active_uid_expires[uid]=now + hid_simulate_uid_stays_active

    # Timeout
    else:

      # Send a keepalive message to the main process so it can trigger timeouts
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])

    # Drop the active UIDs that have timed out
    for uid in list(active_uid_expires):

      if now > active_uid_expires[uid]:

        del(active_uid_expires[uid])
        send_active_uids_update=True

    # Sent the updated list of active UIDs to the main process if needed
    if send_active_uids_update:

      main_in_q.put([HID_LISTENER_UIDS_UPDATE, list(active_uid_expires)])
      send_active_uids_update=False



def adb_listener(main_in_q):
  """On an Android device with USB debugging turned on, run logcat to detect log
  lines from a Tasker script that logs the %nfc_id variable with a prefix in the
  system log upon receiving an NFC read event. The Tasker script is necessary
  to recover the NFC UID, that isn't logged by Android itself. With the Tasker
  script and USB debugging, we're able to exfiltrate the UID from the Android
  device and turn it into a computer-attached reader.

  In addition, to provide persistent mode, the listener also listens for "tag
  off" events from the Android system log. This may be disabled to degrade to
  event mode using only the Tasker script, if the particular Android device or
  Android version doesn't log these events for some reason.

  All this is functional but a bit hacky...
  """

  setproctitle("sirfidal_server_adb_listener")

  adb_proc=[None]

  # SIGCHLD handler to reap defunct adb processes when they quit
  def sigchld_handler(sig, fname):
    os.wait()
    adb_proc[0]=None

  signal(SIGCHLD, sigchld_handler)

  adb_shell_command= \
	"logcat -c" \
	"&&" \
	"logcat -v brief log:I NativeNfcTag:D StNativeNfcTag:D *:S"

  recvbuf=""

  uid_lastseens={}
  active_uids=[]
  send_active_uids_update=True
  tag_present=False

  while True:

    # Try to spawn an adb client
    if not adb_proc[0]:
      try:

        adb_proc[0]=Popen(["adb", "shell", adb_shell_command],
				bufsize=0,
				stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL)

      except KeyboardInterrupt:
        return(-1)
      except:
        adb_proc[0]=None

    if not adb_proc[0]:
      sleep(2)	# Wait a bit before trying to respawn a new adb client
      continue

    # Read ls command outputs from adb - one UID per line expected
    rlines=[]
    b=""
    try:

      if(select([adb_proc[0].stdout], [], [], adb_read_every)[0]):

        try:

          b=adb_proc[0].stdout.read(256).decode("ascii")

        except KeyboardInterrupt:
          return(-1)
        except:
          b=""

        if not b:
          if adb_proc[0]:
            try:
              adb_proc[0].kill()
            except:
              pass
            adb_proc[0]=None
          sleep(2)	# Wait a bit before trying to respawn a new adb client
          continue

        # Split the data into lines
        for c in b:

          if c=="\n" or c=="\r":
            rlines.append(recvbuf)
            recvbuf=""

          elif len(recvbuf)<256 and c.isprintable():
            recvbuf+=c

    except KeyboardInterrupt:
      return(-1)
    except:
      if adb_proc[0]:
        try:
          adb_proc[0].kill()
        except:
          pass
        adb_proc[0]=None
      sleep(2)	# Wait a bit before trying to respawn a new adb client
      continue

    tstamp=int(datetime.now().timestamp())

    # Process the lines from logcat
    for l in rlines:

      # In persistent mode, try to match "Tag lost" lines, mark the tag as
      # absent from the reader and trigger an active UIDs list update if we
      # get one
      if adb_persistent_mode and tag_present and \
		re.match("^.*NativeNfcTag.*Tag lost.*$", l, re.I):
        tag_present=False
        send_active_uids_update=True

      # Extract UIDs logged by the Tasker script
      else:
        m=re.findall("^.*log.*{}([0-9A-F]+).*$".format(
		adb_nfcuid_log_prefix), l, re.I)
        uid=m[0].upper() if m else None

        # If we got a UID add or update its timestamp in the last-seen list.
        # If we add it (new unknown UID), mark the tag as present on the reader
        # and trigger an active UIDs list update
        if uid:
          if uid not in uid_lastseens:
            tag_present=True
            send_active_uids_update=True
          uid_lastseens[uid]=tstamp

    # Remove UID timestamps that are too old from the last-seen list and
    # trigger an active UIDs list update if we're not in persistent mode
    for uid in list(uid_lastseens):
      if tstamp - uid_lastseens[uid] > adb_uid_timeout_in_non_persistent_mode:
        del uid_lastseens[uid]
        if not adb_persistent_mode:
          send_active_uids_update=True

    # Active UIDs update
    if send_active_uids_update:

      # Synchronize the list of active UIDs with the list of last-seen UIDs.
      # If we're in persistent mode and the tag isn't present, consider the
      # list of active UIDs empty instead
      active_uids=[] if adb_persistent_mode and not tag_present \
		else sorted(uid_lastseens)

      # ...send the list to the main process...
      main_in_q.put([ADB_LISTENER_UIDS_UPDATE, active_uids])

      send_active_uids_update=False

    else:

      # ...else send a keepalive message to the main process so it can trigger
      # timeouts
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])



def pm3_listener(workdir, main_in_q):
  """Read UIDs from a Proxmark3 reader.

  The Proxmark3 makes a pretty poor "dumb" reader because it just wasn't build
  for that. It does many thing in software, involving shuttling a lot of data
  from the reader to the computer through the USB port, that dedicated readers
  do internally much faster.

  As a result, the Proxmark3 is quite slow to poll transponders repeatedly.
  It's exceptionally slow when mixing HF and LF transponders, as it takes
  seconds to reconfigure itself for operation on another frequency. So if you
  want any kind of performance, stick to HF- or LF-only transponders.

  Although you'd be better served by a cheap dedicated reader, if you really
  need to use a Proxmark3 with SiRFIDaL (to read transponders that other
  readers can't read for instance), it works.
  """

  setproctitle("sirfidal_server_pm3_listener")

  pm3_proc=[None]

  # SIGCHLD handler to reap defunct proxmark3 processes when they quit or when
  # we kill them
  def sigchld_handler(sig, fname):
    os.wait()
    pm3_proc[0]=None

  signal(SIGCHLD, sigchld_handler)

  # Create a PTY pair to fool the Proxmark3 client into working interactively
  pty_master, pty_slave = openpty()

  # Build the command sequence necessary to perform the reads requested in the
  # parameters
  cmd_sequence_normal=[]
  cmd_sequence_iceman=[]
  lf_samples=0

  if pm3_read_iso14443a:
    cmd_sequence_normal.append("hf 14a reader -3")
    cmd_sequence_iceman.append("hf 14a reader")

  if pm3_read_iso15693:
    cmd_sequence_normal.append("hf 15 cmd sysinfo u")
    cmd_sequence_iceman.append("hf 15 info u")

  if pm3_read_em410x:
    lf_samples=12288
  if pm3_read_fdx:
    lf_samples=15000
  if pm3_read_indala:
    lf_samples=25000

  if lf_samples:
    cmd_sequence_normal.append("lf read s {}".format(lf_samples))
    cmd_sequence_iceman.append("lf read s d {}".format(lf_samples))

  if pm3_read_indala:
    cmd_sequence_normal.append("lf indala demod")
    cmd_sequence_iceman.append("lf indala demod")

  if pm3_read_em410x:
    cmd_sequence_normal.append("lf em 410xdemod")
    cmd_sequence_iceman.append("lf em 410x_demod")

  if pm3_read_fdx:
    cmd_sequence_normal.append("lf fdx demod")
    cmd_sequence_iceman.append("lf fdx demod")

  cmd_sequence=cmd_sequence_normal	# Default sequence

  # Possible Proxmark3 console prompts
  pm3_prompts_regex=re.compile("^(proxmark3>|\[.*\] pm3 -->)$")

  recvbuf=""

  active_uids_temp=[]
  active_uids=[]

  in_indala_multiline_uid=False
  send_active_uids_update=True

  cmd_sequence_i=0

  while True:

    # Try to spawn a Proxmark3 client, making sure we first chdir into its
    # working directory where a fake "proxmark3.log" symlink to /dev/null is
    # already present (normal Proxmark3 client) and without a HOME environment
    # variable so the Iceman client doesn't know where to drop a .proxmark3
    # directory and log things in it
    if not pm3_proc[0]:
      try:

        os.chdir(workdir)
        pm3_proc[0]=Popen([pm3_client, pm3_reader_dev_file], bufsize=0, env={},
				stdin=pty_slave, stdout=PIPE, stderr=DEVNULL)
        timeout_tstamp=int(datetime.now().timestamp()) + pm3_client_comm_timeout

      except KeyboardInterrupt:
        return(-1)
      except:
        pm3_proc[0]=None

    if not pm3_proc[0]:
      sleep(2)	# Wait a bit before trying to respawn a new client
      continue

    # Read lines from the Proxmark3 client
    rlines=[]
    b=""
    try:

      if(select([pm3_proc[0].stdout], [], [], pm3_read_every)[0]):

        try:

          b=pm3_proc[0].stdout.read(256).decode("ascii")

        except KeyboardInterrupt:
          return(-1)
        except:
          b=""

        if not b:
          if pm3_proc[0]:
            try:
              pm3_proc[0].kill()
            except:
              pass
            pm3_proc[0]=None
          sleep(2)	# Wait a bit before trying to respawn a new client
          continue

        # Split the data into lines. If we get a prompt that doesn't end with
        # a CR or LF, make it into a line also
        for c in b:

          if c=="\n" or c=="\r" or pm3_prompts_regex.match(recvbuf):
            rlines.append(recvbuf)
            recvbuf=""

          elif len(recvbuf)<256 and c.isprintable():
            recvbuf+=c

    except KeyboardInterrupt:
      return(-1)
    except:
      if pm3_proc[0]:
        try:
          pm3_proc[0].kill()
        except:
          pass
        pm3_proc[0]=None
      sleep(2)	# Wait a bit before trying to respawn a new client
      continue

    tstamp=int(datetime.now().timestamp())

    # Process the lines from the client
    for l in rlines:

      timeout_tstamp=tstamp + pm3_client_comm_timeout

      # If we detect an RRG/Iceman build, change the command sequence
      if cmd_sequence==cmd_sequence_normal and re.search("RRG/Iceman", l):
        cmd_sequence=cmd_sequence_iceman

      # If we detect a fatal error from the client, forcibly time it out
      if re.search("(proxmark failed|offline|OFFLINE|unknown command)", l):
        timeout_tstamp=0
        break

      # We have a prompt
      if pm3_prompts_regex.match(l):

        # If we reached the end of the command sequence, find out if the
        # complete list of active UIDs has changed and start over
        if cmd_sequence_i >= len(cmd_sequence):

          if active_uids_temp != active_uids:
            active_uids=active_uids_temp
            send_active_uids_update=True

          active_uids_temp=[]

          cmd_sequence_i=0

        # Send the next command in the sequence
        os.write(pty_master, (cmd_sequence[cmd_sequence_i] + "\r").
				encode("ascii"))
        cmd_sequence_i+=1

      uid=None

      # Match Indala multiline UIDs
      if in_indala_multiline_uid:
        m=re.findall("^ \(([0-9a-f]*)\)\s*$", l)
        if m:
          uid=m[0]
          in_indala_multiline_uid=False
        elif not re.match("^[01]+\s*$", l):
          in_indala_multiline_uid=False

      else:
        if re.match("^\s*Indala UID=[01]+\s*$", l):
          in_indala_multiline_uid=True

      # Match single lines containing UIDs
      if not uid and not in_indala_multiline_uid:
        m=re.findall("[\[\]+\s]*" \
			"(UID|EM TAG ID|Indala Found .* Raw\s+0x|Animal ID)" \
			"[\s:]*([0-9a-fA-F- ]+)$", l)
        uid=m[0][1] if m else None

      # We got a UID: strip anything not hexadecimal out of the UID and
      # uppercase it, so it has a chance to be compatible with UIDs read by the
      # other listeners, then add it to the list of active UIDs
      if uid:
        uid="".join([c for c in uid.upper() if c in hexdigits])
        active_uids_temp=sorted(active_uids_temp + [uid])
        if uid not in active_uids:
          active_uids=sorted(active_uids + [uid])
          send_active_uids_update=True

    # If the list of active UIDs has changed, send it to the main process
    if send_active_uids_update:
      main_in_q.put([PM3_LISTENER_UIDS_UPDATE, active_uids])
      send_active_uids_update=False

    else:

      # ...else send a keepalive message to the main process so it can trigger
      # timeouts
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])

    # If we haven't received lines from the Proxmark3 client for too long,
    # kill it
    if tstamp > timeout_tstamp:
      if pm3_proc[0]:
        try:
          pm3_proc[0].kill()
        except:
          pass
        pm3_proc[0]=None
      sleep(2)	# Wait a bit before trying to respawn a new client
      continue



def chameleon_listener(main_in_q):
  """Actively read ISO14443A UIDs from a single Chameleon Mini / Tiny device
  and send the list of active UIDs to the main process. One of the setting slots
  will be automatically reconfigured as a reader, so don't configure it to use
  your Chameleon device for something else when you don't use it as a reader
  with SiRFIDaL
  """

  # Modules
  from serial import Serial

  setproctitle("sirfidal_server_chameleon_listener")

  recvbuf=""

  uid_lastseens={}

  chamdev=None
  send_active_uids_update=True

  while True:

    # Open the reader's device file if it's closed
    if not chamdev:
      try:
        chamdev=Serial(chameleon_dev_file, timeout=0)
        reader_state = 0
      except KeyboardInterrupt:
        return(-1)
      except:
        chamdev=None

    if not chamdev:
      sleep(2)	# Wait a bit to reopen the device
      continue

    # Determine the command to send to the Chameleon - if any
    cmd = None
    if reader_state == 0:	# Query the current slot
      cmd = "SETTING?"
    if reader_state == 3:	# Set the current slot
      cmd = "SETTING={}".format(chameleon_iso14443a_reader_slot)
    elif reader_state == 5:	# Current slot is configured as reader?
      cmd = "CONFIG?"
    elif reader_state == 8:	# Configure current slot as reader
      cmd = "CONFIG=ISO14443A_READER"
    elif reader_state == 10:	# Send a read command
      cmd = "GETUID"

    # Send the command to the Chameleon
    if cmd:

      cmd = (cmd + "\r").encode("ascii")

      try:
        sent=chamdev.write(cmd)

      except KeyboardInterrupt:
        return(-1)
      except:
        sent=-1

      if sent!=len(cmd):
        try:
          chamdev.close()
        except:
          pass
        chamdev=None
        sleep(2)	# Wait a bit to reopen the device
        continue

      reader_state+=1

    # Read UIDs from the reader
    rlines=[]
    b=""
    try:

      if(select([chamdev.fileno()], [], [], chameleon_read_every)[0]):

        try:

          b=os.read(chamdev.fileno(), 256).decode("ascii")

        except KeyboardInterrupt:
          return(-1)
        except:
          b=""

        if not b:
          try:
            chamdev.close()
          except:
            pass
          chamdev=None
          sleep(2)	# Wait a bit to reopen the device
          continue

        # Split the data into lines
        for c in b:

          if c=="\n":
            rlines.append(recvbuf)
            recvbuf=""

          elif len(recvbuf)<256 and c.isprintable() and c!="\r":
            recvbuf+=c

    except KeyboardInterrupt:
      return(-1)
    except:
      try:
        chamdev.close()
      except:
        pass
      chamdev=None
      sleep(2)	# Wait a bit to reopen the device
      continue

    tstamp=int(datetime.now().timestamp())

    uid=""

    # Process the lines from the device
    for l in rlines:

      # Are we waiting for a formatted reply and did we get the correct reply?
      if (reader_state in (1, 6, 11) and l=="101:OK WITH TEXT") or \
		(reader_state in (4, 9) and l=="100:OK"):
        reader_state+=1

      # Are we waiting for a slot number?
      elif reader_state==2 and re.match("^[0-9]$", l):
        reader_state = 5 if int(l)==chameleon_iso14443a_reader_slot else 3

      # Are we waiting for a slot configuration string?
      elif reader_state==7:
        reader_state = 10 if l=="ISO14443A_READER" else 8

      # Did we get a GETUID timeout?
      elif reader_state==11 and l=="203:TIMEOUT":
        reader_state = 10

      # Are we waiting for a UID
      elif reader_state==12 and re.match("^[0-9a-zA-Z]+$", l):
        uid=l.upper()
        reader_state=10

      # Invalid response
      else:
        try:
          chamdev.close()
        except:
          pass
        uid=""
        chamdev=None
        sleep(2)	# Wait a bit to reopen the device
        break

      # If we got a UID, add or update its timestamp in the last-seen list
      if uid:
        if uid not in uid_lastseens:
          send_active_uids_update=True
        uid_lastseens[uid]=tstamp

    # Remove UID timestamps that are too old from the last-seen list
    for uid in list(uid_lastseens):
      if tstamp - uid_lastseens[uid] > chameleon_uid_not_sent_inactive_timeout:
        del uid_lastseens[uid]
        send_active_uids_update=True

    # If the active UIDs have changed...
    if send_active_uids_update:

      # ...send the list to the main process...
      main_in_q.put([CHAMELEON_LISTENER_UIDS_UPDATE, list(uid_lastseens)])
      send_active_uids_update=False

    else:

      # ...else send a keepalive message to the main process so it can trigger
      # timeouts
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])



def ufr_listener(main_in_q):
  """Receive UIDs from a uFR or uFR Nano Online reader configured in slave mode,
  then send the active UID to the main process.
  """

  setproctitle("sirfidal_server_ufr_listener")

  # Modules
  import pyufr

  uFR=pyufr.uFR()

  ufr=None
  uids=[]

  close_device = False

  uids_off_report_tstamp=0
  last_sent_uids=None
  send_update=True

  while True:

    now=datetime.now().timestamp()

    # Close the uFR device if needed
    if close_device:
      ufr.close()
      ufr=None
      close_device=False
      sleep(2)	# Wait a bit to reopen the device

    # Open the uFR device if needed
    if not ufr:

      try:
        ufr=uFR.open(ufr_device, restore_on_close = True)

        # Disable tag emulation and ad-hoc mode, in case we find the reader in
        # a strange state
        ufr.tag_emulation_stop()
        ufr.ad_hoc_emulation_stop()

        # Set asynchronous ID sending mode if needed, or enable anti-collision
        # if we use polled mode, and put the red LED on once and for all if we
        # do power saving in polled mode
        if not ufr_polled_mode:
          ufr.disable_anti_collision()
          ufr.set_card_id_send_conf(True)
          recheck_conn_at_tstamp=now + ufr_device_check_every
        else:
          ufr.enable_anti_collision()
          if ufr_polled_power_saving:
            ufr.red_light_control(True)

      except:
        sleep(2)	# Wait a bit to reopen the device
        continue

      red_led_state=True
      ufr_no_rgb2=ufr_no_rgb2_card_off
      set_leds=True

    # Should we set the LEDs?
    if set_leds:

      # Try to set the red LED on if the reader isn't asleep. Fail silently
      if not (ufr_polled_mode and ufr_polled_power_saving):
        try:
          ufr.red_light_control(red_led_state)
        except:
          pass

      # Try to set the Nano Online LEDs if we have RGB values. Fail silently
      if ufr_no_rgb1 and ufr_no_rgb2:
        try:
          ufr.esp_set_display_data(ufr_no_rgb1, ufr_no_rgb2, 0)
        except:
          pass

      set_leds = False

    # Should we recheck the connection with the reader?
    if not ufr_polled_mode and now > recheck_conn_at_tstamp:
      try:
        ufr.get_firmware_version()
        recheck_conn_at_tstamp=now + ufr_device_check_every
      except:
        close_device=True
        continue

    # Get a UID from the uFR reader using the polling of asynchronous method
    last_uids=uids
    try:
      if ufr_polled_mode:
        if ufr_polled_power_saving:
          try:
            ufr.leave_sleep_mode()
          except:
            ufr.leave_sleep_mode()
        ufr.enum_cards()
        uids=sorted(ufr.list_cards())
        if ufr_polled_power_saving:
          ufr.enter_sleep_mode()
      else:
        uid=ufr.get_async_id(ufr_read_every)
        uids=[uid] if uid else []
        recheck_conn_at_tstamp=now + ufr_device_check_every

    except TimeoutError:
      if ufr_polled_mode:
        close_device=True
        continue
      else:
        # Send a keepalive message to the main process so it can trigger
        # timeouts
        main_in_q.put([MAIN_PROCESS_KEEPALIVE])

    except KeyboardInterrupt:
      try:
        ufr.close()
      except:
        pass
      break

    except:
      close_device=True
      continue

    # Did the UID change, or go off long enough for us to take action?
    if uids!=last_uids or (not uids and uids_off_report_tstamp):

      send_update=True

      # Prevent UID-off events from being reported too fast
      if not uids:
        if not uids_off_report_tstamp:
          uids_off_report_tstamp=now + ufr_debounce_delay
          send_update=False
        elif now < uids_off_report_tstamp:
          send_update=False
        else:
          uids_off_report_tstamp=0
      else:
        uids_off_report_tstamp=0
        if uids==last_sent_uids:
          send_update=False

    # Should we send an updated list of UIDs to the main process?
    if send_update:

      # Send the list to the main process
      main_in_q.put([UFR_LISTENER_UIDS_UPDATE, uids])
      last_sent_uids=uids

      # Update the state of the LEDs
      red_led_state=not uids
      ufr_no_rgb2=ufr_no_rgb2_card_on if uids else ufr_no_rgb2_card_off
      set_leds=True

      send_update=False

    # If nothing has changed, send a keepalive message to the main process in
    # polled mode, so it can trigger timeouts
    elif ufr_polled_mode:
      main_in_q.put([MAIN_PROCESS_KEEPALIVE])

      # Wait a bit to prevent polling too fast
      remaining_wait=ufr_read_every - datetime.now().timestamp() + now
      if remaining_wait > 0:
        sleep(remaining_wait)



def server(main_in_q, sock):
  """Handle client connections to the server
  """

  setproctitle("sirfidal_server_client_server")

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

    # Get the passwd name of the calling process' UID. It should exist, so if
    # we get an error, this is fishy and we should close the connection.
    try:
      pw_name=pwd.getpwuid(uid).pw_name
    except:
      conn.close()
      continue

    # Create a pipe for the main process to send messages to the client handler
    main_out_p, chandler_out_p = Pipe()

    # Spawn a client handler
    Process(target=client_handler, args=(
		  pid,
		  uid,
		  gid,
		  pw_name,
		  main_in_q,
		  main_out_p,
		  chandler_out_p,
		  conn
		)).start()



def client_handler(pid, uid, gid, pw_name,
			main_in_q, main_out_p, chandler_out_p, conn):
  """Handler for communications between the client and the main process
  """

  setproctitle("sirfidal_server_client_handler_{}".format(pid))

  # Drop our privileges to that of the client, so we can't write to the
  # encrypted file if the calling process can't either. Also set umask so
  # that if we have to create the file as root, root will be able to read and
  # write to it, users belonging to the right group will only be able to write
  # (to add or delete UIDs without being able to read the encrypted file) and
  # others may not access it in any way.
  try:
    os.setgroups(os.getgrouplist(pw_name, gid))
    os.setgid(gid)
    os.setuid(uid)
    os.umask(0o057)
  except:
    return(0)

  # Client receive buffer
  crecvbuf=""

  # Client send buffer
  csendbuf=""

  force_stop_tstamp=None

  # Inform the main process that we have a new client
  main_in_q.put([NEW_CLIENT, [pid, pw_name, main_out_p]])
  new_client_ack=False

  while True:

    # Do we have something to send to the client?
    if(csendbuf):
      if(conn):
        try:
          conn.sendall((csendbuf + "\n").encode("ascii"))
        except:	# Oops, the socket was closed
          # inform the main process we want to stop and close the socket.
          main_in_q.put([CLIENT_HANDLER_STOP_REQUEST, [pid, main_out_p]])
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

          # Also send the UID in plaintext if the main process deems it okay
          if msg[1][1]:
            csendbuf+=" {}".format(msg[1][1])

          continue

        # The main process reports an update in the number of active UIDs: sent
        # it to the client
        elif msg[0]==NBUIDS_UPDATE:
          csendbuf="NBUIDS {} {}".format(msg[1][0], msg[1][1])
          continue

        # The main process reports an update in the list of active UIDs: sent
        # it to the client
        elif msg[0]==UIDS_UPDATE:
          csendbuf="UIDS{}".format("".join([" " + s for s in msg[1][0]]))
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
        try:
          b=fd.recv(256).decode("ascii")
        except:	# Oops, the socket was closed
          # inform the main process we want to stop and close the socket.
          main_in_q.put([CLIENT_HANDLER_STOP_REQUEST, [pid, main_out_p]])
          conn.close()
          conn=None
          continue

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

          # WATCHNBUIDS request
          if l=="WATCHNBUIDS":
            main_in_q.put([WATCHNBUIDS_REQUEST, [pid]])

          # WATCHUIDS request: the user must be root. If not, deny the request
          elif l=="WATCHUIDS":
            if uid==0:
              main_in_q.put([WATCHUIDS_REQUEST, [pid]])
            else:
              csendbuf="NOAUTH"

          else:
            # WAITAUTH request
            m=re.findall("^WAITAUTH\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
            if m:
              main_in_q.put([WAITAUTH_REQUEST, [pid, m[0][0], float(m[0][1])]])

            else:
              # ADDUSER request
              m=re.findall("^ADDUSER\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
              if m:
                main_in_q.put([ADDUSER_REQUEST, [pid, m[0][0], float(m[0][1])]])

              else:
                # DELUSER request
                m=re.findall("^DELUSER\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
                if m:
                  main_in_q.put([DELUSER_REQUEST, [pid, m[0][0], \
				float(m[0][1])]])



def is_remote_user(pid):
  """Attempt to determine if the user is logged in locally or remotely by
  tracing the parent processes and trying to find telltale process names.
  This is very poor security, and won't prevent a mildly determined bad guy
  with a local account from logging in if the PAM modules is configured as 1FA.
  But we keep it around as a last ditch effort to keep honest people honest, if
  the user has ignored the warning in the README.
  """
  pprocess=psutil.Process(pid=pid)

  while(pprocess and pprocess.name() not in remote_user_parent_process_names):
    pprocess=pprocess.parent()

  return(pprocess!=None)



def load_encruids():
  """Read and verify the content of the encrypted UIDs file, if it has been
  modified. In case of read or format error, delete the encrypted UIDs in
  memory and returns None. Otherwise return False if the file didn't need
  reloading, and True if it was reread
  """

  global encruids_file_mtime
  global encruids

  # Get the file's modification time
  try:
    mt=os.stat(encrypted_uids_file).st_mtime
  except:
    encruids=[]
    return(None)

  # Check if the file has changed
  if not encruids_file_mtime:
    encruids_file_mtime=mt
  else:
    if mt <= encruids_file_mtime:
      return(False)

  # Re-read the file
  try:
    with open(encrypted_uids_file, "r") as f:
      new_encruids=json.load(f)
  except:
    encruids=[]
    return(None)

  # Validate the structure of the JSON format
  if not isinstance(new_encruids, list):
    encruids=[]
    return(None)

  for entry in new_encruids:
    if not (
	  isinstance(entry, list) and
          len(entry)==2 and
	  isinstance(entry[0], str) and
	  isinstance(entry[1], str)
	):
      encruids=[]
      return(None)

  # Update the encrypted UIDs currently in memory
  encruids_file_mtime=mt
  encruids=new_encruids
  return(True)



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

  setproctitle("sirfidal_server")

  # Main routine's input queue
  main_in_q=Queue()

  # If we use a normal Proxmark3 client as a backend, create a "proxmark3.log"
  # symlink to /dev/null in its working directory to prevent it from logging
  # anything
  if watch_pm3:

    pm3_logfile=os.path.join(pm3_client_workdir, "proxmark3.log")

    if os.path.exists(pm3_logfile):
      if not os.path.islink(pm3_logfile):
        print("Error: {} already exists and isn't a symlink. Giving up.".format(
						pm3_logfile))
        return(-1)
    else:
      try:
        os.symlink(os.devnull, pm3_logfile)
      except:
        print("Error: cannot symlink {} to {}. Giving up.".format(
						pm3_logfile, os.devnull))
        return(-1)

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

  # Start the HID listener
  if watch_hid:
    Process(target=hid_listener, args=(main_in_q,)).start()

  # Start the ADB listener
  if watch_adb:
    Process(target=adb_listener, args=(main_in_q,)).start()

  # Start the Proxmark3 listener
  if watch_pm3:
    Process(target=pm3_listener, args=(pm3_client_workdir,main_in_q,)).start()

  # Start the Chameleon listener
  if watch_chameleon:
    Process(target=chameleon_listener, args=(main_in_q,)).start()

  # Start the uFR listener
  if watch_ufr:
    Process(target=ufr_listener, args=(main_in_q,)).start()



  # Main process
  active_pcsc_uids=[]
  active_serial_uids=[]
  active_hid_uids=[]
  active_adb_uids=[]
  active_pm3_uids=[]
  active_chameleon_uids=[]
  active_ufr_uids=[]
  active_uids=[]
  active_uids_prev=None
  auth_cache={}
  auth_uid_cache={}
  send_active_uids_update=False
  active_clients={}

  while True:

    # Get a message from another process
    msg=main_in_q.get()
    msg_tstamp=datetime.now().timestamp()

    # Skip all tests for other kinds of messages if it's a keepalive message
    if msg[0] != MAIN_PROCESS_KEEPALIVE:

      # The message is an update of the active UIDs from one of the listeners
      if msg[0] in (PCSC_LISTENER_UIDS_UPDATE, SERIAL_LISTENER_UIDS_UPDATE,
		HID_LISTENER_UIDS_UPDATE, ADB_LISTENER_UIDS_UPDATE,
		PM3_LISTENER_UIDS_UPDATE, CHAMELEON_LISTENER_UIDS_UPDATE,
		UFR_LISTENER_UIDS_UPDATE):

        if msg[0] == PCSC_LISTENER_UIDS_UPDATE:
          active_pcsc_uids=msg[1]
        elif msg[0] == SERIAL_LISTENER_UIDS_UPDATE:
          active_serial_uids=msg[1]
        elif msg[0] == HID_LISTENER_UIDS_UPDATE:
          active_hid_uids=msg[1]
        elif msg[0] == ADB_LISTENER_UIDS_UPDATE:
          active_adb_uids=msg[1]
        elif msg[0] == PM3_LISTENER_UIDS_UPDATE:
          active_pm3_uids=msg[1]
        elif msg[0] == CHAMELEON_LISTENER_UIDS_UPDATE:
          active_chameleon_uids=msg[1]
        elif msg[0] == UFR_LISTENER_UIDS_UPDATE:
          active_ufr_uids=msg[1]

        # Save the previous list of active UIDs
        active_uids_prev=active_uids

        # Merge the lists of UIDs from all the listeners
        active_uids=list(set(sorted(active_pcsc_uids + active_serial_uids + \
				active_hid_uids + active_adb_uids + \
				active_pm3_uids + active_chameleon_uids + \
				active_ufr_uids)))

        send_active_uids_update=True

      # New client notification from a client handler
      elif msg[0] == NEW_CLIENT:

        # Create this client in the list of active clients and assign it the
        # void request to time out the client if it stays idle too long
        active_clients[msg[1][0]]=client()
        active_clients[msg[1][0]].pw_name=msg[1][1]
        active_clients[msg[1][0]].main_out_p=msg[1][2]
        active_clients[msg[1][0]].request=VOID_REQUEST
        active_clients[msg[1][0]].expires=msg_tstamp + \
			client_force_close_socket_timeout
        active_clients[msg[1][0]].main_out_p.send([NEW_CLIENT_ACK])

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

      # The client requested to watch the evolution of the list of UIDs
      # themselves in real time
      elif msg[0] == WATCHUIDS_REQUEST:

        # Update this client's request in the list of active requests.
        # No timeout for this request: it's up to the client to close the
        # socket when it's done
        active_clients[msg[1][0]].request=WATCHUIDS_REQUEST
        active_clients[msg[1][0]].user=None
        active_clients[msg[1][0]].expires=None

      # Remove a client from the list of active clients and tell the handler
      # to stop
      elif msg[0] == CLIENT_HANDLER_STOP_REQUEST:

        del(active_clients[msg[1][0]])
        msg[1][1].send([CLIENT_HANDLER_STOP])



    # Try to reload the encrypted UIDs file. If it needed reloading, or if the
    # list of active UIDs has changed, wipe the user authentication cache
    if load_encruids() or send_active_uids_update:
      auth_cache={}
      auth_uid_cache={}

    # Process the active clients' requests
    for cpid in active_clients:

      auth=False
      auth_uid=None

      # If we arrive here following a keepalive message, only process timeouts
      if msg[0] != MAIN_PROCESS_KEEPALIVE:

        # Request to watch the evolution of the number of active UIDs in
        # real-time: send an update if one is available
        if active_clients[cpid].request == WATCHNBUIDS_REQUEST and \
		send_active_uids_update and active_uids_prev != None and \
		 len(active_uids) != len(active_uids_prev):
          active_clients[cpid].main_out_p.send([NBUIDS_UPDATE, \
		[len(active_uids), len(active_uids) - len(active_uids_prev)]])

        # Request to watch the evolution of the list of active UIDs in
        # real-time: send an update if one is available
        if active_clients[cpid].request == WATCHUIDS_REQUEST and \
		active_uids_prev != None and \
		(active_clients[cpid].new_request or \
		(active_uids != active_uids_prev and send_active_uids_update)):
          active_clients[cpid].main_out_p.send([UIDS_UPDATE, [active_uids]])
          active_clients[cpid].new_request=False

        # Authentication request
        elif active_clients[cpid].request == WAITAUTH_REQUEST:

          # First try to find a cached authentication status for that user
          if active_clients[cpid].user in auth_cache:

            auth=auth_cache[active_clients[cpid].user]
            auth_uid=auth_uid_cache[active_clients[cpid].user]

          # Second try to match one of the active UIDs with one of the
          # registered encrypted UIDs associated with that user
          else:

            for uid in active_uids:
              for registered_user, registered_uid_encr in encruids:
                if registered_user == active_clients[cpid].user and crypt(
			  uid,
			  registered_uid_encr
			) == registered_uid_encr:
                  auth=True	# User authenticated...
                  auth_uid=uid	#...with this UID
                  break
              if auth:
                break

            # Cache the result of this authentication - valid as long as the
            # list of active UIDs doesn't change and the encrypted IDs file
            # isn't reloaded - to avoid calling crypt() each time a requesting
            # process asks an authentication and nothing has changed since the
            # previous request
            auth_cache[active_clients[cpid].user]=auth
            auth_uid_cache[active_clients[cpid].user]=auth_uid

        # Add user request: if we have exactly one active UID, associate it
        # with the requested user
        elif active_clients[cpid].request == ADDUSER_REQUEST and \
		len(active_uids)==1:

          new_encruids=encruids.copy()

          # Don't replace an existing user <-> UID association: if we find one,
          # notify the client handler and replace the request with a fresh void
          # request and associated timeout
          for registered_user, registered_uid_encr in new_encruids:
            if registered_user == active_clients[cpid].user and crypt(
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
		  crypt(active_uids[0], mksalt())
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

          # Find one or more existing user <-> UID associations and remove
          # them if needed
          assoc_deleted=False
          new_encruids=[]
          for registered_user, registered_uid_encr in encruids:
            if registered_user == active_clients[cpid].user and (
			active_clients[cpid].expires == None or crypt(
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
      # a fresh void request and associated timeout. If the requesting process
      # owner is the same as the user they request an authentication for, they
      # have the right to know their own UID, so send it along.
      if active_clients[cpid].request == WAITAUTH_REQUEST and \
		(auth or active_clients[cpid].expires==None or \
		msg_tstamp >= active_clients[cpid].expires):
        active_clients[cpid].main_out_p.send([AUTH_RESULT, [AUTH_OK if auth
		else AUTH_NOK, auth_uid if auth and \
		active_clients[cpid].user == active_clients[cpid].pw_name \
		else None]])
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
