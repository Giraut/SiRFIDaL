#!/usr/bin/python3
"""This program is the cornerstone of the SiRFIDaL system: it provides secure
authentication services for local processes wishing to authenticate a user
against a RFID or NFC UID, or manipulate the list of user / UID / optional
secondary authentication token associations without exposing UIDs or
authentication tokens to unauthorized processes.

By default, only startup messages and error messages are printed out. To output
extended debug messages, invoke with -d / --debug. To suppress startup
messages, invoke with -s / --silent.

The script performs the following functions:

* Background functions

  - Read RFID / NFC UIDs from different connected readers: one or more PC/SC
    readers, serial readers, HID readers, Android devices used as
    external NFC readers, Proxmark3 readers, Chameleon Mini / Tiny,
    uFR / uFR Nano Online in slave mode, readers reporting UIDs using HTTP
    GET or POST or TCP readers may be watched concurrently

  - Internally maintain a list of of currently active UIDs - that is, the list
    of UIDs of RFID or NFC transponders currently readable by the readers at
    any given time

  - Manipulate the user/UID/authtok association database contained in the
    encrypted UIDs file. Each association is either:

    - One username and one UID
    - One username, one UID and one optional secondary authentication token

    If the authentication token is present in the association, it is used
    typically by the SiRFIDaL PAM module to set authtok in the PAM stack, so
    that things like keyring or encrypted directories may be unlocked by the
    relevant PAM modules when logging in with SiRFIDaL, provided the optional
    secondary authentication token matches the user's regular login password.

    The SiRFIDaL server reads and writes the encrypted UIDs file, creates and
    deletes user/UID or user/UID/authtok associations according to which user
    is allowed to do what operation.

* Server for local frontend programs to request one of the following services:

  - Authenticate a user against one of the currently registered user/UID or
    user/UID/authtok associations, waiting for up to a requested time for a
    successful UID authentication, then return the authentication status.

    If the requestor is root or the same user they request authentication for,
    the list of authenticating UIDs is also returned if the authentication is
    successful.

    If the user is root, authtoks are also returned if the authentication is
    successful, if found in the matching associations.

  - Add an authenticated user - i.e. associate a user and a UID, and optinally
    an authtok - then save this association in the encrypted UIDs file.
    Only root may request an association with a new user or UID. However, a
    normal user with an existing user/UID association may request that a new
    authtok be added to the association.

  - Delete an authenticated user - i.e. delete a user/UID association,
    including an optional associated authtok from the encrypted UIDs file.
    Only root or the user requesting the deletion for themselves may perform
    this operation.

  - Delete all associations for an authenticated user in the encrypted UIDs
    file, including any optional associated authtoks, from the the encrypted
    UIDs file. Only root or the user requesting the deletion for themselves may
    perform this operation.

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

  - Acquire and release mutexes: useful for clients that need a simple locking
    mechanism without resorting to OS-specific atomic functions

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
Server replies: AUTHOK [authenticating UID #1[:authtok #1]] [authenticating
                       UID#2[:authtok #2]] ...
                NOAUTH

Service:        Watch the evolution of the number of active UIDs in real-time
Client sends:   WATCHNBUIDS
Server replies: NBUIDS <new nb of active UIDS> <change since previous update>

Service:        Watch the evolution of the list of active UIDs in real-time
Client sends:   WATCHUIDS
Server replies: UIDS [active UID #1] [active UID #2] [active UID #3] ...
                NOAUTH

Service:        Add a user/UID/authtok in the encrypted UIDs file
                (authtok optional)
Client sends:   ADDUSER <user> <max wait (int or float) in s> [authtok]
Server replies: TIMEOUT
                EXISTS
                WRITEERR
                OK
		NOAUTH

Service:        Delete a user/UID/authtok from the encrypted UIDs file
Client sends:   DELUSER <user> <max wait (int or float) in s>
Server replies: TIMEOUT
                NONE
                WRITEERR
                OK
		NOAUTH

Service:        Delete all entries matching a userin the encrypted UIDs file
Client sends:   DELUSER <user> -1
Server replies: NONE
                WRITEERR
                OK
		NOAUTH

Service:        Acquire a named mutex
Client sends:   MUTEXACQ <name> <max wait (int or float) in s>
Server replies: OK
                EXISTS

Service:        Release a named mutex
Client sends:   MUTEXREL <name>
Server replies: OK
                NONE

The server will reply to any other request it doesn't understand with:
		UNKNOWN

After receiving a reply to a WAITAUTH, ADDUSER or DELUSER request, the client
is expected to close the socket within a certain grace period. The client may
lodge a new request within that grace period. If it doesn't, the server will
force-close the socket at the end of the grace period.

After receiving a WATCHNBUIDS or WATCHUIDS request, the server continuously
sends updates and never closes the socket. It's up to the client to close its
end of the socket to terminate the request. At any given time, the client may
lodge a new request, canceling and replacing the running WATCHNBUIDS or
WATCHUIDS request.
"""

### Parameters
# Location of the configuration file
config_file = "/etc/sirfidal_server_parameters.py"



### Modules
import os
import re
import sys
import pwd
import json
import struct
import psutil
import inspect
import secrets
import argparse
from pty import openpty
from select import select
from time import time, sleep
from string import hexdigits
from signal import signal, SIGCHLD
from passlib.hash import sha512_crypt
from setproctitle import setproctitle
from filelock import FileLock, Timeout
from base64 import b64encode, b64decode
from subprocess import Popen, DEVNULL, PIPE
from multiprocessing import Process, Queue, Pipe, Pool, cpu_count
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from socket import socket, timeout, AF_UNIX, SOCK_STREAM, SOL_SOCKET, \
			SO_REUSEADDR, SO_PEERCRED



### Configuration parameters
try:
  exec(open(config_file).read())
except Exception as e:
  print("Error reading {}: {}".format(config_file, e))
  sys.exit(1)

max_mutexes_per_client = 2
max_mutex_acq_wait = 30 #s



### Defines
LISTENER_UIDS_UPDATE        = 0
NEW_CLIENT                  = 1
NEW_CLIENT_ACK              = 2
VOID_REQUEST                = 3
VOID_REQUEST_TIMEOUT        = 4
WAITAUTH_REQUEST            = 5
AUTH_RESULT                 = 6
AUTH_OK                     = 7
AUTH_NOK                    = 8
WATCHNBUIDS_REQUEST         = 9
NBUIDS_UPDATE               = 10
WATCHUIDS_REQUEST           = 11
UIDS_UPDATE                 = 12
ADDUSER_REQUEST             = 13
DELUSER_REQUEST             = 14
ENCRUIDS_UPDATE_OK          = 15
ENCRUIDS_UPDATE_ERR_EXISTS  = 16
ENCRUIDS_UPDATE_ERR_NONE    = 17
ENCRUIDS_UPDATE_ERR_TIMEOUT = 18
ENCRUIDS_UPDATE_ERR_WRITE   = 19
MUTEXACQ_REQUEST            = 20
MUTEXREL_REQUEST            = 21
MUTEX_OK                    = 22
MUTEX_ERR_EXISTS            = 23
MUTEX_ERR_NONE              = 24
CLIENT_HANDLER_STOP_REQUEST = 25
CLIENT_HANDLER_STOP         = 26

VERBOSITY_SILENT = 0
VERBOSITY_NORMAL = 1
VERBOSITY_DEBUG  = 2



### Global variables
encruids_file_mtime =  None
encruids = []
verbosity = VERBOSITY_NORMAL



### Classes
class client:
  """Active client request
  """

  def __init__(self):

    self.uid = None
    self.pw_name = None
    self.main_out_p = None
    self.request = None
    self.name = None
    self.authtok = None
    self.mutexes = set()
    self.expires = None
    self.new_request = True



### subroutines / subprocesses
def log(min_verbosity, fct_id, msg):
  """Display the name of the calling function and its message if the verbosity
  level is at least the message's minimum verbosity.
  """

  if verbosity >= min_verbosity:
    print("[{}] {}{}".format(inspect.stack()[1].function,
				"[{}] ".format(fct_id) if fct_id else "", msg))



def pcsc_listener(main_in_q, listener_id, params):
  """Periodically read the UIDs from one or more PC/SC readers and send the
  list of active UIDs to the main process
  """

  # Modules
  import smartcard.scard as sc

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  readers_regex = params["readers_regex"]
  poll_every = params["poll_every"]

  # Wait for the status on the connected PC/SC readers to change and get the
  # list of active PC/SC UIDs when it does
  all_readers = None
  all_readers_prev = None
  hcontext = None

  readers = None

  while True:

    active_uids = []
    poll_start_tstamp = time()

    # Wait on a PC/SC card's status change
    all_readers = []

    if not hcontext:

      r, hcontext = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)

      if r != sc.SCARD_S_SUCCESS:
        log(VERBOSITY_DEBUG, listener_id, "Cannot get context")
        del(hcontext)
        hcontext = None

    if hcontext:

      _, all_readers = sc.SCardListReaders(hcontext, [])

      if not all_readers:
        log(VERBOSITY_DEBUG, listener_id, "No readers")
        sc.SCardReleaseContext(hcontext)
        del(hcontext)
        hcontext = None

    if all_readers_prev != all_readers:

      all_readers_prev = all_readers

      # Only work with readers whose name match the regular expression
      readers = [r for r in all_readers \
			if re.match("^" + readers_regex + "$", r)]
      if readers:

        rs = []
        for i in range(len(readers)):
          rs += [(readers[i], sc.SCARD_STATE_UNAWARE)]

        try:
          _, rs = sc.SCardGetStatusChange(hcontext, 0, rs)

        except KeyboardInterrupt:
          return -1

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          sc.SCardReleaseContext(hcontext)
          del(hcontext)
          hcontext = None
          readers = []

      if all_readers and not readers:
        log(VERBOSITY_DEBUG, listener_id, "No reader names matching regex")

    if readers:

      try:
        rv, rs = sc.SCardGetStatusChange(hcontext, int(poll_every * 1000), rs)

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        del(hcontext)
        hcontext = None
        readers = []

    # If a card's status has changed, re-read all the UIDs
    if readers and rv == sc.SCARD_S_SUCCESS:
      for reader in readers:
        try:
          hresult, hcard, dwActiveProtocol = sc.SCardConnect(hcontext,
				reader, sc.SCARD_SHARE_SHARED,
				sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1)
          hresult, response = sc.SCardTransmit(hcard, dwActiveProtocol,
						[0xFF, 0xCA, 0x00, 0x00, 0x00])

          uid = "".join("{:02X}".format(b) for b in response)

          if uid[-4:] == "9000":
            uid = uid[:-4]

          if uid:
            active_uids.append(uid)

        except KeyboardInterrupt:
          return -1

        except Exception as e:
          err = str(e)
          if verbosity >= VERBOSITY_DEBUG and not \
		"SCardTransmit> returned NULL without setting an error" in err:
            log(VERBOSITY_DEBUG, listener_id, err)

      # Send the list of active UIDs to the main process
      main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, active_uids)))

    # Sleep long enough to meet the required polling rate
    sleep(max(0, poll_every - time() + poll_start_tstamp))



def nfcpy_listener(main_in_q, listener_id, params):
  """Periodically read UIDs directly from a USB or serial reader supported
  by the nfcpy Python module (http://nfcpy.org/ - list of supported devices:
  https://nfcpy.readthedocs.io/en/latest/overview.html#supported-devices) and
  send the list of active UIDs to the main process. Useful if you don't want to
  setup PC/SC and you don't care about sharing the reader with other
  applications.
  """

  # Modules
  import nfc

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  device = params["device"]
  flash_and_beep = params["flash_and_beep"]
  poll_every = params["poll_every"]

  # Bitrate + type of targets to search: type A, B and F tags at the lowest
  # bitrate
  targets = ("106A", "106B", "212F")

  clf = None
  active_uids = None

  close_device = False
  exit_errcode = 0

  while True:

    # Close the device and/or exit if needed
    if close_device or exit_errcode:
      try:
        clf.close()
      except:
        pass
      del(clf)
      clf = None

      # Exit if needed
      if exit_errcode:
        return exit_errcode

      sleep(2)	# Wait a bit to reopen the device
      close_device = False

    try:

      # Open the device and set the targets
      if clf is None:
        try:
          clf = nfc.ContactlessFrontend()

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          continue

        try:
          if not clf.open(device):
            log(VERBOSITY_DEBUG, listener_id, "Error opening device {}"
						.format(device))
            close_device = True
            continue

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          close_device = True
          continue

        try:
          ts = [nfc.clf.RemoteTarget(t) for t in targets]

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          close_device = True
          continue

      poll_start_tstamp = time()

      # Read UIDs from the reader
      try:
        t = clf.sense(*ts)

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_device = True
        continue

      active_uids_prev = active_uids
      active_uids = [] if t is None else \
			["".join([format(v, "02X") for v in t.sdd_res])]

      # Send the list of active UIDs to the main process if it has changed
      if active_uids_prev is None or set(active_uids_prev) != set(active_uids):
        if flash_and_beep:
          try:
            (clf.device.turn_on_led_and_buzzer if active_uids else \
		clf.device.turn_off_led_and_buzzer)()

          except Exception as e:
            log(VERBOSITY_DEBUG, listener_id, e)
            close_device = True
            continue

        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, active_uids)))

      # Sleep long enough to meet the required polling rate
      sleep(max(0, poll_every - time() + poll_start_tstamp))

    except KeyboardInterrupt:
      exit_errcode = -1



def serial_listener(main_in_q, listener_id, params):
  """Read UIDs from a serial reader and send the list of active UIDs to the
  main process. The reader may be a repeating reader - i.e. one that sends the
  UIDs of the active transponders repeatedly as long as they remain readable  -
  or a single-shot reader that sends the UIDs only once upon first reading. The
  UIDs timeout parameter should be slightly higher than the refresh rate of the
  former, and however long is appropriate for the considered application with
  the latter.
  """

  # Modules
  import serial

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  device = params["device"]
  baudrate = params["baudrate"]
  bytesize = (serial.FIVEBITS, serial.SIXBITS,
		serial.SEVENBITS, serial.EIGHTBITS)[params["bytesize"] - 5]
  parity = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN,
		"O": serial.PARITY_ODD, "M": serial.PARITY_MARK,
		"S": serial.PARITY_SPACE}[params["parity"]]
  stopbits = {1: serial.STOPBITS_ONE, 1.5: serial.STOPBITS_ONE_POINT_FIVE,
		2: serial.STOPBITS_TWO}[params["stopbits"]]

  uid = ""
  serdev = None

  close_device = False

  while True:

    # Close the serial device if needed
    if close_device:
      try:
        serdev.close()
      except:
        pass
      serdev = None
      sleep(2)	# Wait a bit to reopen the device

      close_device = False

    # Open the serial device
    if serdev is None:
      try:
        serdev = serial.Serial(port = device,
				baudrate = baudrate,
				bytesize = bytesize,
				parity = parity,
				stopbits = stopbits,
				timeout = None)

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        serdev = None

    if serdev is None:
      sleep(2)	# Wait a bit to reopen the device
      continue

    # Read UIDs from the reader
    try:
      c = serdev.read(1).decode("ascii")

    except KeyboardInterrupt:
      return -1

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      close_device = True
      continue

    if not c:
      log(VERBOSITY_DEBUG, listener_id, "Error reading from {}".format(device))
      close_device = True
      continue

    if c in "\r\n":
      if uid:
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))
        uid = ""

    elif c in hexdigits and len(uid) < 256:
      uid += c.upper()



def halo_listener(main_in_q, listener_id, params):
  """Read UIDs from a Halo Scanner connected to USB and send the list of active
  UIDs to the main process
  """

  # Modules
  import serial

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  device = params["device"]
  new_firmware = params["new_firmware"]
  auto_rescan = params["auto_rescan"]
  alive_min_temp = params["alive_min_temp"]
  alive_max_temp = params["alive_max_temp"]
  alive_prefix = params["alive_prefix"].upper()

  serdev = None

  close_device = False

  while True:

    # Close the serial device if needed
    if close_device:
      try:
        serdev.close()
      except:
        pass
      serdev = None
      sleep(2)	# Wait a bit to reopen the device

      close_device = False

    # Open the serial device
    if serdev is None:
      try:
        serdev = serial.Serial(port = device,
				baudrate = 115200,
				bytesize = serial.EIGHTBITS,
				parity = serial.PARITY_NONE,
				stopbits = serial.STOPBITS_ONE,
				timeout = None)

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        serdev = None

      scanner_state = 0

    if serdev is None:
      sleep(2)	# Wait a bit to reopen the device
      continue

    # Send the appropriate command to the scanner
    if scanner_state in (0, 6, 10):

      sleep(.5)

      # Connect command
      if scanner_state == 0:
        cmd = b"PA"

      # Serial output on command
      elif scanner_state == 6:
        cmd = b"RO1" if new_firmware else b"RO\x01"

      # Auto-rescan command
      elif scanner_state == 10:
        cmd = b"SX"

      try:
        serdev.write(cmd + b"\r")

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_device = True
        continue

      scanner_state += 1

    # Read data from the reader: wait forever when waiting for the UID, wait
    # only a fraction of a second when waiting for the subsequent temperature
    # value
    serdev.timeout = 0.1 if scanner_state == 9 else None
    try:
      c = serdev.read(1).decode("ascii")

    except KeyboardInterrupt:
      return -1

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      close_device = True
      continue

    # Did we read nothing at all?
    if not c:

      # If we were waiting for a temperature value, we timed out. So simply
      # send the UID to the main process as-is if we have one
      if scanner_state == 9:
        if uid:
          main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))
          uid = ""
        scanner_state = 10 if new_firmware and auto_rescan else 8
        continue

      # If we weren't waiting for a temperature value, we had no timeout set so
      # this is a genuine read error
      else:
        log(VERBOSITY_DEBUG, listener_id, "Error reading from {}"
						.format(device))
        close_device = True
        continue

    # Receive the connection acknowledgment
    if 1 <= scanner_state <= 5:
      if c == "Halo\x00"[scanner_state - 1]:
        scanner_state += 1
      else:
        scanner_state = 0

    # Receive the serial output on acknowledgement
    elif scanner_state == 7:
      if c == "Z":
        scanner_state = 8
        recvbuf = ""
      elif c == "?":
        scanner_state = 6
      else:
        scanner_state = 0

    # Receive a UID
    elif scanner_state == 8:
      if c == "\r":
        if recvbuf:
          uid = recvbuf
          recvbuf = ""
          scanner_state = 9

      elif c in hexdigits and len(recvbuf) < 256:
        recvbuf += c.upper()

    # Receive a temperature value. If it lies between the minimum and maximum
    # temperature values for a living being, prefix the UID with the special
    # "live" hex prefix - the idea being that cloned chips with the same UID
    # but without a temperature value, or with a temperature value that is not
    # compatible with a live implant, will not get prefixed, therefore will
    # not authenticate a previously registered UID with the "live" prefix
    elif scanner_state == 9:
      if c == "\r":
        if uid:
          if re.match(r"^[0-9]+\.[0-9]+C$", recvbuf):
            temp = float(recvbuf[:-1])
            if alive_min_temp <= temp <= alive_max_temp:
              uid = alive_prefix + uid
          main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))
          uid = ""
        recvbuf = ""
        scanner_state = 10 if new_firmware and auto_rescan else 8

      elif c in "0123456789.C" and len(recvbuf) < 256:
        recvbuf += c.upper()

    # Receive the auto-restart scan acknowledgement
    elif scanner_state == 11:
      if c == "Z":
        scanner_state = 8
        recvbuf = ""
      elif c == "?":
        scanner_state = 11
      else:
        scanner_state = 0



def hid_listener(main_in_q, listener_id, params):
  """Read UIDs from a single HID reader (aka a "keyboard wedge") and send the
  list of active UIDs to the main process.

  Sadly, almost all keyboard wedges are one-shot readers, so the UIDs timeout
  parameter should be whatever appropriate time the UIDs should stay active
  for for the considered application.
  """

  # Modules
  from evdev import InputDevice, categorize, ecodes

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  device = params["device"]

  SC_LSHIFT = 42
  SC_RSHIFT = 54
  SC_ENTER  = 28
  KEYUP     = 0
  KEYDOWN   = 1

  scancodes_us_kbd = {
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

  shifted = 0

  uid = ""
  hiddev = None

  close_device = False

  while True:

    # Close the HID device if needed
    if close_device:
      if hiddev is not None:
        try:
          hiddev.close()
        except:
          pass
        hiddev = None
      sleep(2)	# Wait a bit to reopen the device

      close_device = False

    # Grab the HID device for exclusive use by us
    if hiddev is None:
      try:
        hiddev = InputDevice(device)
        hiddev.grab()

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_device = True
        continue

    # Get events from the HID reader
    try:
      select([hiddev.fd], [], [], None)
      events = list(hiddev.read())

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      close_device = True
      continue

    for event in events:

      if event.type == ecodes.EV_KEY:
        d = categorize(event)

        if d.scancode == SC_LSHIFT or d.scancode == SC_RSHIFT:
          if d.keystate == KEYDOWN or d.keystate == KEYUP:
            shifted = 1 if d.keystate == KEYDOWN else 0

        elif d.scancode == SC_ENTER:
          if uid:
            main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))
            uid = ""

        elif d.keystate == KEYDOWN and len(uid) < 256:
          c = scancodes_us_kbd.get(d.scancode, ["", ""])[shifted]
          if c in hexdigits:
            uid += c.upper()



def android_listener(main_in_q, listener_id, params):
  """On an Android device with USB debugging turned on, this listener runs
  logcat to detect log lines from a Tasker script that logs the %nfc_id
  variable with a prefix in the system log upon receiving an NFC read event.
  The Tasker script is necessary to recover the NFC UID, that isn't
  logged by Android itself. With the Tasker script and USB debugging, we're
  able to exfiltrate the UID from the Android device and turn it into a
  computer-attached reader.

  In addition, to provide persistent mode, the listener also listens for "tag
  off" events from the Android system log. If, for any reason, Android doesn't
  doesn't log these events, set the UIDs timeout parameters to some positive
  number of seconds to make the listener work in event mode.

  All this is functional but a bit hacky...
  """

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  proc = [None]

  # SIGCHLD handler to reap defunct adb processes
  def adb_listener_sigchld_handler(sig, fname):
    log(VERBOSITY_DEBUG, listener_id, "ADB client died")
    sleep(.5)	# Give the client's outputs a chance to flush before reaping
    os.wait()

  signal(SIGCHLD, adb_listener_sigchld_handler)

  # Parameters
  persistent_mode = params["uids_timeout"] is None
  client = params["client"]
  logcat_prefix = params["logcat_prefix"]
  adb_shell_command = \
	"logcat -c" \
	"&&" \
	"logcat -v brief log:I NativeNfcTag:D StNativeNfcTag:D *:S"

  recvbuf = ""

  uid_lastseens = {}
  active_uids = []
  send_active_uids_update = True
  tag_present = False

  kill_client = False
  force_uids_timeout_on_client_kill = False

  while True:

    # Kill the currently running client if needed
    if kill_client:

      # Send an empty UIDs list to the main process, to force-timeout any
      # lingering UIDs if we're working in persistent mode
      if persistent_mode and force_uids_timeout_on_client_kill:
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, ())))
        force_uids_timeout_on_client_kill = False

      try:
        proc[0].kill()
      except:
        pass
      proc[0] = None
      sleep(2)	# Wait a bit before trying to respawn a new client

      kill_client = False

    # Spawn a new adb client
    if proc[0] is None:
      try:
        proc[0] = Popen([client, "shell", adb_shell_command],
				bufsize = 0, stdin = DEVNULL,
				stdout = PIPE, stderr = PIPE)

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        proc[0] = None

    if proc[0] is None:
      sleep(2)	# Wait a bit before trying to respawn a new adb client
      continue

    # Read lines from the ADB client's stdout or stderr
    rlines = []
    b = ""

    try:
      fds = select([proc[0].stdout, proc[0].stderr], [], [], None)[0]

      if fds:

        # Read the client's stdout
        if proc[0].stdout in fds:
          try:
            b = proc[0].stdout.read(256).decode("ascii")

          except KeyboardInterrupt:
            return -1

          except Exception as e:
            log(VERBOSITY_DEBUG, listener_id, e)
            kill_client = True
            continue

          if not b:
            log(VERBOSITY_DEBUG, listener_id,
				"Error reading ADB client's stdout")
            kill_client = True
            continue

          # Split the data into lines and log them
          for c in b:

            if c in "\r\n":
              log(VERBOSITY_DEBUG, listener_id, "[client stdout] {}"
						.format(recvbuf))
              rlines.append(recvbuf)
              recvbuf = ""

            elif c.isprintable() and len(recvbuf) < 256:
              recvbuf += c

        # Read the client's stderr, for debugging purposes
        elif proc[0].stderr in fds:
          try:
            b = proc[0].stderr.read(256).decode("ascii")

          except KeyboardInterrupt:
            return -1

          except Exception as e:
            log(VERBOSITY_DEBUG, listener_id, e)
            kill_client = True
            continue

          if not b:
            log(VERBOSITY_DEBUG, listener_id,
				"Error reading ADB client's stderr")
            kill_client = True
            continue

          # Split the data into lines and log them
          for c in b:

            if c in "\r\n":
              log(VERBOSITY_DEBUG, listener_id, "[client stderr] {}"
						.format(recvbuf))
              recvbuf = ""

            elif  c.isprintable() and len(recvbuf) < 256:
              recvbuf += c

      # Error waiting for data from stdout or stderr
      else:
        log(VERBOSITY_DEBUG, listener_id, "Error waiting for data from ADB "
						"client's stdout or stderr")
        kill_client = True
        continue

    except KeyboardInterrupt:
      return -1

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      kill_client = True
      continue

    # Process the lines from logcat
    for l in rlines:

      # Try to match "Tag lost" lines and send an empty active UIDs list to the
      # main process if we get one
      if re.match("^.*NativeNfcTag.*Tag lost.*$", l, re.I):
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, ())))
        force_uids_timeout_on_client_kill = False

      # Extract UIDs logged by the Tasker script
      else:
        m = re.findall("^.*log.*{}([0-9A-F]+).*$".format(logcat_prefix),
			l, re.I)

        # If we got a UID, send it as a one-UID active UIDs list to the main
        # process
        if m:
          main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (m[0].upper(),))))
          force_uids_timeout_on_client_kill = True



def proxmark3_listener(main_in_q, listener_id, params):
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

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  proc = [None]

  # SIGCHLD handler to reap defunct proxmark3 processes
  def proxmark3_listener_sigchld_handler(sig, fname):
    log(VERBOSITY_DEBUG, listener_id, "Proxmark3 client died")
    sleep(.5)	# Give the client's outputs a chance to flush before reaping
    os.wait()

  signal(SIGCHLD, proxmark3_listener_sigchld_handler)

  # Parameters
  client_workdir = params["client_workdir"]
  client = params["client"]
  device = params["device"]
  client_timeout = params["client_timeout"]
  poll_throttle = params["poll_throttle"]

  # Build the command sequence necessary to perform the reads requested in the
  # parameters
  cmd_sequence_normal = []
  cmd_sequence_iceman = []
  lf_samples = 0

  if params["read_iso14443a"]:
    cmd_sequence_normal.append("hf 14a reader -3")
    cmd_sequence_iceman.append("hf 14a reader")

  if params["read_iso15693"]:
    cmd_sequence_normal.append("hf 15 cmd sysinfo u")
    cmd_sequence_iceman.append("hf 15 info u")

  if params["read_em410x"]:
    lf_samples = 12288

  if params["read_fdx"]:
    lf_samples = 15000

  if params["read_indala"]:
    lf_samples = 25000

  if lf_samples:
    cmd_sequence_normal.append("lf read s {}".format(lf_samples))
    cmd_sequence_iceman.append("lf read s d {}".format(lf_samples))

  if params["read_indala"]:
    cmd_sequence_normal.append("lf indala demod")
    cmd_sequence_iceman.append("lf indala demod")

  if params["read_em410x"]:
    cmd_sequence_normal.append("lf em 410xdemod")
    cmd_sequence_iceman.append("lf em 410x_demod")

  if params["read_fdx"]:
    cmd_sequence_normal.append("lf fdx demod")
    cmd_sequence_iceman.append("lf fdx demod")

  cmd_sequence = cmd_sequence_normal	# Default sequence

  # Create a PTY pair to fool the Proxmark3 client into working interactively
  pty_master, pty_slave = openpty()

  # Possible Proxmark3 console prompts
  prompts_regex = re.compile(r"^(proxmark3>|\[.*\] pm3 -->)$")

  recvbuf = ""

  in_indala_multiline_uid = False

  active_uids = []

  kill_client = False
  force_uids_timeout_on_client_kill = False

  while True:

    # Kill the currently running client if needed
    if kill_client:

      # Send an empty UIDs list to the main process, to force-timeout any
      # lingering UIDs
      if force_uids_timeout_on_client_kill:
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, ())))
        force_uids_timeout_on_client_kill = False

      try:
        proc[0].kill()
      except:
        pass
      proc[0] = None
      sleep(2)	# Wait a bit before trying to respawn a new client

      kill_client = False

    # Spawn a Proxmark3 client
    if proc[0] is None:
      try:
        # Make sure we first chdir into the client's working directory, where
        # a fake "proxmark3.log" symlink to /dev/null is already present
        # (normal Proxmark3 client) and without a HOME environment variable
        # so the Iceman client doesn't know where to drop a .proxmark3
        # directory and log things into it
        os.chdir(client_workdir)

        # Try to spawn a Proxmark3 client
        proc[0] = Popen([client, device] if device else [client],
			bufsize = 0, env = {},
			stdin = pty_slave, stdout = PIPE, stderr = PIPE)
        timeout_tstamp = time() + client_timeout

        # Start the command sequence at the beginning
        cmd_sequence_i = 0
        poll_start_tstamp = time()

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        proc[0] = None

    if proc[0] is None:
      sleep(2)	# Wait a bit before trying to respawn a new client
      continue

    # Read lines from the Proxmark3 client's stdout or stderr
    rlines = []
    b = ""

    try:
      fds = select([proc[0].stdout, proc[0].stderr], [], [], client_timeout)[0]

      if fds:

        # Read the client's stdout
        if proc[0].stdout in fds:
          try:
            b = proc[0].stdout.read(256).decode("ascii")

          except KeyboardInterrupt:
            return -1

          except Exception as e:
            log(VERBOSITY_DEBUG, listener_id, e)
            kill_client = True
            continue

          if not b:
            log(VERBOSITY_DEBUG, listener_id,
				"Error reading Proxmark3 client's stdout")
            kill_client = True
            continue

          # Split the data into lines. If we get a prompt that doesn't end with
          # a CR or LF, make it into a line also. Log the lines
          for c in b:

            if c in "\r\n" or prompts_regex.match(recvbuf):
              log(VERBOSITY_DEBUG, listener_id, "[client stdout] {}"
						.format(recvbuf))
              rlines.append(recvbuf)
              recvbuf = ""

            elif c.isprintable() and len(recvbuf) < 256:
              recvbuf += c

        # Read the client's stderr, for debugging purposes
        elif proc[0].stderr in fds:
          try:
            b = proc[0].stderr.read(256).decode("ascii")

          except KeyboardInterrupt:
            return -1

          except Exception as e:
            log(VERBOSITY_DEBUG, listener_id, e)
            kill_client = True
            continue

          if not b:
            log(VERBOSITY_DEBUG, listener_id,
				"Error reading Proxmark3 client's stderr")
            kill_client = True
            continue

          # Split the data into lines and log them
          for c in b:

            if c in "\r\n":
              log(VERBOSITY_DEBUG, listener_id, "[client stderr] {}"
						.format(recvbuf))
              recvbuf = ""

            elif  c.isprintable() and len(recvbuf) < 256:
              recvbuf += c

      # Timeout: the Proxmark3 client is unresponsive
      else:
        log(VERBOSITY_DEBUG, listener_id, "Proxmark3 client unresponsive")
        kill_client = True
        continue

    except KeyboardInterrupt:
      return -1

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      kill_client = True
      continue

    tstamp = time()

    # Process the lines from the client
    for l in rlines:

      timeout_tstamp = tstamp + client_timeout

      # If we detect an RRG/Iceman build, change the command sequence
      if cmd_sequence == cmd_sequence_normal and re.search("RRG/Iceman", l):
        cmd_sequence = cmd_sequence_iceman

      # If we detect a fatal error from the client, forcibly time it out
      if re.search("(proxmark failed|offline|OFFLINE|unknown command)", l):
        timeout_tstamp = 0
        break

      # We have a prompt
      if prompts_regex.match(l):

        # If we reached the end of the command sequence, send the list of
        # active UIDs to the main process and start over
        if cmd_sequence_i >= len(cmd_sequence):
          main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, active_uids)))
          force_uids_timeout_on_client_kill = True
          active_uids = []

          # If the Proxmark3 works fast enough, sleep a bit to avoid
          # polling too fast
          sleep(max(0, poll_throttle - time() + poll_start_tstamp))

          # Restart the command sequence
          cmd_sequence_i = 0
          poll_start_tstamp = time()

        # Send the next command in the sequence
        try:
          os.write(pty_master, (cmd_sequence[cmd_sequence_i] + "\r").
				encode("ascii"))

        except KeyboardInterrupt:
          return -1

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          kill_client = True
          continue

        cmd_sequence_i += 1

      uid = None

      # Match Indala multiline UIDs
      if in_indala_multiline_uid:
        m = re.findall(r"^ \(([0-9a-f]*)\)\s*$", l)
        if m:
          uid = m[0]
          in_indala_multiline_uid = False
        elif not re.match(r"^[01]+\s*$", l):
          in_indala_multiline_uid = False

      else:
        if re.match(r"^\s*Indala UID=[01]+\s*$", l):
          in_indala_multiline_uid = True

      # Match single lines containing UIDs
      if uid is None and not in_indala_multiline_uid:
        m = re.findall(r"[\[\]+\s]*" \
			r"(UID|EM TAG ID|Indala Found .* Raw\s+0x|Animal ID)" \
			r"[\s:]*([0-9a-fA-F- ]+)$", l)
        uid = m[0][1] if m else None

      # If we got a UID, add it to the list of active UIDs
      if uid:
        uid = "".join([c for c in uid.upper() if c in hexdigits])
        active_uids = sorted(set(active_uids) | set([uid]))



def chameleon_listener(main_in_q, listener_id, params):
  """Actively read ISO14443A UIDs from a single Chameleon Mini / Tiny device
  and send the list of active UIDs to the main process. One of the setting slots
  must be configured as a reader
  """

  # Modules
  import serial

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  device = params["device"]
  poll_throttle = params["uids_timeout"] / 2

  recvbuf = ""
  chamdev = None

  close_device = False

  while True:

    # Close the Chameleon device if needed
    if close_device:
      try:
        chamdev.close()
      except:
        pass
      chamdev = None
      sleep(2)	# Wait a bit to reopen the device

      close_device = False

    # Open the Chameleon device
    if chamdev is None:
      try:
        chamdev = serial.Serial(port = device,
				baudrate = 9600,
				bytesize = serial.EIGHTBITS,
				parity = serial.PARITY_NONE,
				stopbits = serial.STOPBITS_ONE,
				timeout = None)
        reader_state = 0
        start_slot = -1
        poll_start_tstamp = time()

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        chamdev = None

    if chamdev is None:
      sleep(2)	# Wait a bit to reopen the device
      continue

    # Determine the command to send to the Chameleon - if any
    cmd = None
    if reader_state == 0:	# Query the current slot
      cmd = "SETTING?\r"
    elif reader_state == 3:	# Is the current slot configured as reader?
      cmd = "CONFIG?\r"
    elif reader_state == 6:	# Select the slot
      cmd = "SETTING={}\r".format(slot)
    elif reader_state == 8:	# Send a read command
      cmd = "GETUID\r"
    elif reader_state == 11:	# Turn the field on
      cmd = "FIELD=1\r"
    elif reader_state == 13:	# Turn the field off
      cmd = "FIELD=0\r"

    # Send the command to the Chameleon
    if cmd:

      try:
        sent = chamdev.write(cmd.encode("ascii"))

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_device = True
        continue

      if sent != len(cmd):
        log(VERBOSITY_DEBUG, listener_id, "Error writing to {}".format(device))
        close_device = True
        continue

      reader_state += 1

    # Read responses from the reader
    l = ""

    try:
      c = chamdev.read(1).decode("ascii")

    except KeyboardInterrupt:
      return -1

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      close_device = True
      continue

    if not c:
      log(VERBOSITY_DEBUG, listener_id, "Error reading from {}".format(device))
      close_device = True
      continue

    if c == "\n":
      l = recvbuf
      recvbuf = ""

    elif c.isprintable() and c != "\r" and len(recvbuf)<256:
      recvbuf += c

    # Process the lines from the device
    if l:

      # Are we waiting for a formatted reply and did we get the correct reply?
      if (reader_state in (1, 4, 9) and l == "101:OK WITH TEXT") or \
		(reader_state in (7, 12, 14) and l == "100:OK"):

        if reader_state == 7:		# Slot selection command successful
          reader_state = 3
        elif reader_state == 12:	# Field on command successful
          sleep(.1)
          reader_state += 1
        elif reader_state == 14:	# Field off command successful
          sleep(1)
          reader_state = 11
        else:				# Any other response line
          reader_state += 1

      # Are we waiting for a slot number?
      elif reader_state == 2 and re.match("^[0-9]$", l):
        try:
          slot = int(l)
          slot = -1 if slot < 1 else 8 if slot > 8 else slot
        except:
          slot = -1

        # If we got an error getting the slot number, close the reader
        if slot == -1:
          log(VERBOSITY_DEBUG, listener_id, "Couldn't get slot number")
          close_device = True
          continue

        start_slot = slot
        reader_state = 3

      # Are we waiting for a slot configuration string?
      elif reader_state == 5:
        if l == "ISO14443A_READER":
          reader_state = 8
        else:
          # Scan the next slot
          slot = slot + 1 if slot < 8 else 1

          # If we scanned all the slots, start flashing the field (which also
          # flashes the white LED) to tell the user we can't do anything with
          # the reader
          if slot == start_slot:
            reader_state = 11
          else:
            reader_state = 6

      # Did we get a GETUID timeout?
      elif reader_state == 9 and l == "203:TIMEOUT":
        reader_state = 8

      # Are we waiting for a UID?
      elif reader_state == 10 and re.match("^[0-9A-F]+$", l, re.I):

        # Send it as a one-UID active UIDs list to the main
        # process
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (l.upper(),))))

        # Sleep long enough to avoid polling uselessly
        sleep(max(0, poll_throttle - time() + poll_start_tstamp))
        poll_start_tstamp = time()

        reader_state = 8

      # Invalid response
      else:
        log(VERBOSITY_DEBUG, listener_id, "Invalid response")
        close_device = True
        continue



def ufr_listener(main_in_q, listener_id, params):
  """Receive UIDs from a uFR or uFR Nano Online reader configured in slave mode,
  then send the active UID to the main process.
  """

  # Modules
  import pyufr

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  device = params["device"]
  poll_every = params["poll_every"]
  polled_mode = poll_every is not None
  polled_power_saving = params["poll_powersave"]
  debounce_delay = params["debounce_delay"]
  no_rgb1 = params["no_rgb1"]
  no_rgb2_on = params["no_rgb2_on"]
  no_rgb2_off = params["no_rgb2_off"]
  conn_recheck_every = params["conn_watchdog"]

  uFR = pyufr.uFR()

  ufr = None
  uids = []

  uids_off_debounce_tstamp = None

  close_device = False
  force_uids_timeout_on_device_close = False

  while True:

    # Close the uFR device if needed
    if close_device:

      # Send an empty UIDs list to the main process, to force-timeout any
      # lingering UIDs if we're working in polled (i.e. persistent) mode
      if polled_mode and force_uids_timeout_on_device_close:
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, ())))
        force_uids_timeout_on_device_close = False

      try:
        ufr.close()
      except:
        pass
      ufr = None
      sleep(2)	# Wait a bit to reopen the device

      close_device = False

    start_tstamp = time()

    # Open the uFR device
    if not ufr:
      try:
        ufr = uFR.open(device, restore_on_close = True)

        # Disable tag emulation and ad-hoc mode, in case we find the reader in
        # a strange state
        ufr.tag_emulation_stop()
        ufr.ad_hoc_emulation_stop()

        # Set asynchronous ID sending mode if needed, or enable anti-collision
        # if we use polled mode, and put the red LED on once and for all if we
        # do power saving in polled mode
        if polled_mode:
          ufr.enable_anti_collision()
        else:
          ufr.disable_anti_collision()
          ufr.set_card_id_send_conf(True)
          recheck_conn_at_tstamp = start_tstamp + conn_recheck_every

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_device = True
        continue

      red_led_state = True
      red_led_state_prev = None

      no_rgb2 = no_rgb2_off
      no_rgb2_prev = None

      first_run = True

    # If we get here right after opening the uFR device, go set the LEDs
    # righaway
    if not first_run:

      # Should we recheck the connection with the reader?
      if not polled_mode and start_tstamp > recheck_conn_at_tstamp:
        try:
          ufr.get_firmware_version()
          recheck_conn_at_tstamp = start_tstamp + conn_recheck_every
        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          close_device = True
          continue

      # Get a UID from the uFR reader using the polling of asynchronous method
      try:
        if polled_mode:
          if polled_power_saving:
            try:
              ufr.leave_sleep_mode()
            except:
              ufr.leave_sleep_mode()
          ufr.enum_cards()
          uids = sorted(ufr.list_cards())
          if polled_power_saving:
            ufr.enter_sleep_mode()
        else:
          uid = ufr.get_async_id(conn_recheck_every \
				if uids_off_debounce_tstamp is None \
				else debounce_delay)
          uids = [uid] if uid else []
          recheck_conn_at_tstamp = time() + conn_recheck_every

      except TimeoutError:
        if polled_mode:
          close_device = True
          continue
        else:
          uids = []

      except KeyboardInterrupt:
        try:
          ufr.close()
        except:
          pass
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_device = True
        continue

      end_tstamp = time()

      # Send the UIDs and change the state of the LEDs depending on whether one
      # or more UID is active. But if we have no active UIDs and we're in async
      # mode, only do so after a debounce delay
      if not polled_mode and not uids and uids_off_debounce_tstamp is None:
        uids_off_debounce_tstamp = end_tstamp + debounce_delay

      if polled_mode or uids or (uids_off_debounce_tstamp is not None and \
		end_tstamp > uids_off_debounce_tstamp):

        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, uids)))
        force_uids_timeout_on_device_close = True

        red_led_state = False if uids else True
        no_rgb2 = no_rgb2_on if uids else no_rgb2_off

        uids_off_debounce_tstamp = None

    # Set the red LED if needed. Fail silently
    if red_led_state_prev is None or (red_led_state != red_led_state_prev and \
		not (polled_mode and polled_power_saving)):
      try:
        ufr.red_light_control(red_led_state)
      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        pass
      red_led_state_prev = red_led_state

    # Set the Nano Online LEDs if needed, if we have RGB values. Fail silently
    if no_rgb1 is not None and no_rgb2 is not None and no_rgb2 != no_rgb2_prev:
      try:
        ufr.esp_set_display_data(no_rgb1, no_rgb2, 0)
      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        pass
      no_rgb2_prev = no_rgb2

    # If we're in polled mode and it's not the first run, wait a bit to prevent
    # polling too fast
    if not first_run and polled_mode:
      sleep(max(0, poll_every - end_tstamp + start_tstamp))

    first_run = False



def http_listener(main_in_q, listener_id, params):
  """Run a simplistic web server to receive UIDs in HTTP GET or POST messages,
  then send the list of active UIDs to the main process.
  """

  # Modules
  from http.server import BaseHTTPRequestHandler, HTTPServer

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  bind_addr =  params["bind_address"]
  bind_port =  params["bind_port"]
  get_data_fmt = params["get_data_fmt"]
  get_reply = params["get_reply"]
  post_data_fmt = params["post_data_fmt"]
  post_reply = params["post_reply"]

  # Handler class
  class handler_class(BaseHTTPRequestHandler):

    # HTTP GET method
    def do_GET(self):

      if not get_data_fmt:
        return

      # If the GET URL contain a valid UID, send it as a one-UID active UIDs
      # list to the main process
      m = re.findall(get_data_fmt, self.path)
      if m:
        uid = "".join([c for c in m[0].upper() if c in hexdigits])
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))

      # Reply to the HTTP client
      self.send_response(200)
      self.send_header("Content-type", "text/plain")
      self.end_headers()
      self.wfile.write(get_reply.encode("ascii"))

    # HTTP POST method
    def do_POST(self):

      if not post_data_fmt:
        return

      # If the POST URL contain a valid UID, send it as a one-UID active UIDs
      # list to the main process
      content_length = int(self.headers['Content-Length'])
      post_data = self.rfile.read(content_length).decode("ascii") \
			if content_length>0 else ""

      # Does the POST data contain a valid UID?
      m = re.findall(post_data_fmt, post_data)
      if m:
        uid = "".join([c for c in m[0].upper() if c in hexdigits])
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))

      # Reply to the HTTP client
      self.send_response(200)
      self.send_header('Content-type', 'text/plain')
      self.end_headers()
      self.wfile.write(post_reply.encode("ascii"))

    # Empty logger to suppress logging messages
    def log_message(self, format, *args):
      return

  while True:

    # Set up the HTTP server
    try:
      httpd = HTTPServer((bind_addr, bind_port), handler_class)

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      sleep(2)	# Wait a bit before trying to set up the HTTP server again
      continue

    # Run the HTTP server
    try:
      httpd.serve_forever()

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      try:
        httpd.server_close()
      except:
        pass
      sleep(2)	# Wait a bit before trying to set up the HTTP server again



def tcp_listener(main_in_q, listener_id, params):
  """Read UIDs from a TCP socket then send the list of active UIDs to the
  main process.
  """

  # Modules
  from socket import socket, timeout, AF_INET, SOCK_STREAM

  setproctitle("sirfidal_listener_{}".format(listener_id))
  log(VERBOSITY_NORMAL, listener_id, "Started")

  # Parameters
  server_addr =  params["server_address"]
  server_port =  params["server_port"]
  tcp_keepalive =  params["tcp_keepalive"]

  recvbuf = ""
  sock = None

  close_socket = False

  while True:

    # Close the socket if needed
    if close_socket:
      try:
        sock.close()
      except:
        pass
      sock = None
      sleep(2)	# Wait a bit to reopen the socket

      close_socket = False

    start_tstamp = time()

    # Open the socket
    if sock is None:
      try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(None)
        sock.connect((server_addr, server_port))

      except KeyboardInterrupt:
        return -1

      except Exception as e:
        log(VERBOSITY_DEBUG, listener_id, e)
        close_socket = True
        continue

    # Read UIDs from the socket
    rlines = []
    b = ""

    try:

      if(select([sock.fileno()], [], [], tcp_keepalive)[0]):

        try:
          b = sock.recv(256).decode("ascii")

        except KeyboardInterrupt:
          return -1

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          close_socket = True
          continue

        if not b:
          log(VERBOSITY_DEBUG, listener_id, "Error reading from socket")
          close_socket = True
          continue

        # Split the data into lines
        for c in b:

          if c in "\r\n":
            rlines.append(recvbuf)
            recvbuf = ""

          elif c.isprintable() and len(recvbuf)<256:
            recvbuf += c

      # Timeout: send a keepalive message to the TCP server to detect if the
      # link went down
      else:
        try:
          sock.sendall(b"\n")

        except KeyboardInterrupt:
          return -1

        except Exception as e:
          log(VERBOSITY_DEBUG, listener_id, e)
          close_socket = True

        continue

    except KeyboardInterrupt:
      return -1

    except Exception as e:
      log(VERBOSITY_DEBUG, listener_id, e)
      close_socket = True
      continue

    # Process the lines from the device
    for l in rlines:

      # If we got a UID, send it as a one-UID active UIDs list to the main
      # process
      uid = "".join([c for c in l.upper() if c in hexdigits])
      if uid:
        main_in_q.put((LISTENER_UIDS_UPDATE, (listener_id, (uid,))))



def server(main_in_q, sock):
  """Handle client connections to the server
  """

  setproctitle("sirfidal_server_client_server")
  log(VERBOSITY_NORMAL, "", "Started")

  # SIGCHLD handler to reap defunct client handlers when they exit
  def sigchld_handler(sig, fname):
    os.wait()

  # Run the server
  signal(SIGCHLD, sigchld_handler)

  while True:

    # Wait for a connection
    conn, _ = sock.accept()

    # Get the calling process' PID, UID and GID
    creds = conn.getsockopt(SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)

    # Get the passwd name of the calling process' UID. It should exist, so if
    # we get an error, this is fishy and we should close the connection.
    try:
      pw_name = pwd.getpwuid(uid).pw_name
    except:
      conn.close()
      continue

    # Create a pipe for the main process to send messages to the client handler
    main_out_p, chandler_out_p = Pipe()

    # Spawn a client handler
    Process(target = client_handler, args = (pid, uid, gid, pw_name,
						is_remote_user(pid),
						main_in_q, main_out_p,
						chandler_out_p, conn)).start()



def client_handler(pid, uid, gid, pw_name, is_remote_user,
			main_in_q, main_out_p, chandler_out_p, conn):
  """Handler for communications between the client and the main process
  """

  setproctitle("sirfidal_server_client_handler_{}".format(pid))

  # If we run as root, drop our privileges to that of the client
  if os.getuid() == 0:
    try:
      os.setgroups(os.getgrouplist(pw_name, gid))
      os.setgid(gid)
      os.setuid(uid)
    except:
      return 0

  # Client receive buffer
  crecvbuf = ""

  # Client send buffer
  csendbuf = ""

  force_stop_tstamp = None

  # Inform the main process that we have a new client
  main_in_q.put((NEW_CLIENT, (pid, uid, pw_name, main_out_p)))
  new_client_ack = False

  while True:

    # Do we have something to send to the client?
    if(csendbuf):
      if(conn is not None):
        try:
          conn.sendall((csendbuf + "\n").encode("ascii"))
        except:	# Oops, the socket was closed
          # inform the main process we want to stop and close the socket.
          main_in_q.put((CLIENT_HANDLER_STOP_REQUEST, (pid, main_out_p)))
          conn.close()
          conn = None
      csendbuf = ""

    # Wait for either the main process of the client to send us something
    fds = select([chandler_out_p] + \
			([conn] if conn is not None and new_client_ack else []),
			[], [], 1)[0]

    # Did we hit the timeout?
    if not fds:

      # Should we force-close the socket and quit?
      if force_stop_tstamp and time() > force_stop_tstamp:

        main_in_q.put((CLIENT_HANDLER_STOP_REQUEST, (pid, main_out_p)))
        conn.close()
        conn = None
        continue

    for fd in fds:

      # Message from the main process
      if fd == chandler_out_p:

        msg = fd.recv()

        # New client notification aknowledgment
        if msg[0] == NEW_CLIENT_ACK:
          new_client_ack = True
          continue

        # The main process reports an authentication result: send the result
        # to the client. Also send the authenticating UIDs, or UID/authtok pairs
        # the main process deems it okay
        elif msg[0] == AUTH_RESULT:
          csendbuf = "AUTHOK" if msg[1][0] == AUTH_OK else "NOAUTH"
          if msg[1][1]:
            csendbuf += " {}".format(" ".join([uid for uid in msg[1][1]]))
          continue

        # The main process reports an update in the number of active UIDs: sent
        # it to the client
        elif msg[0] == NBUIDS_UPDATE:
          csendbuf = "NBUIDS {} {}".format(msg[1][0], msg[1][1])
          continue

        # The main process reports an update in the list of active UIDs: sent
        # it to the client
        elif msg[0] == UIDS_UPDATE:
          csendbuf = "UIDS{}".format("".join([" " + s for s in msg[1][0]]))
          continue

        # The main process reports successfully updating the encrypted UIDs:
        # notify the client
        elif msg[0] == ENCRUIDS_UPDATE_OK:
          csendbuf = "OK"
          continue

        # The main process reports an error updating the encrypted UIDs
        # because the user/UID or user/UID/authtok association already exists:
        # notify the client
        elif msg[0] == ENCRUIDS_UPDATE_ERR_EXISTS:
          csendbuf = "EXISTS"
          continue

        # The main process reports an error updating the encrypted UIDs
        # because it hasn't found a matching user/UID association to delete:
        # notify the client
        elif msg[0] == ENCRUIDS_UPDATE_ERR_NONE:
          csendbuf = "NONE"
          continue

        # The main process reports a timeout waiting for a UID to associate
        # or disassociate with a user/authtok
        elif msg[0] == ENCRUIDS_UPDATE_ERR_TIMEOUT:
          csendbuf = "TIMEOUT"
          continue

        # The main process reports an error writing the encrypted UIDs file:
        # notify the client
        elif msg[0] == ENCRUIDS_UPDATE_ERR_WRITE:
          csendbuf = "WRITEERR"
          continue

        # The main process reports success for a mutex acquisition or release:
        # notify the client
        elif msg[0] == MUTEX_OK:
          csendbuf = "OK"
          continue

        # The main process reports failure to acquire a mutex: notify the client
        elif msg[0] == MUTEX_ERR_EXISTS:
          csendbuf = "EXISTS"
          continue

        # The main process reports failure to release a mutex: notify the client
        elif msg[0] == MUTEX_ERR_NONE:
          csendbuf = "NONE"
          continue

        # The main process reports a void request timeout (in other words, the
        # client has failed to place a valid request in time).
        elif msg[0] == VOID_REQUEST_TIMEOUT:

          # Inform the main process we want to stop and close the socket.
          main_in_q.put((CLIENT_HANDLER_STOP_REQUEST, (pid, main_out_p)))
          conn.close()
          conn = None

          continue

        # The main process instructs us to stop
        elif msg[0] == CLIENT_HANDLER_STOP:
          return 0

      # Message from the client
      elif fd == conn:

        # Get data from the socket
        try:
          b = fd.recv(256).decode("ascii")
        except:	# Oops, the socket was closed
          # inform the main process we want to stop and close the socket.
          main_in_q.put((CLIENT_HANDLER_STOP_REQUEST, (pid, main_out_p)))
          conn.close()
          conn = None
          continue

        # If we got nothing, the client has closed its end of the socket.
        # Inform the main process we want to stop and close the socket.
        if len(b) == 0:
          main_in_q.put((CLIENT_HANDLER_STOP_REQUEST, (pid, main_out_p)))
          conn.close()
          conn = None
          continue

        # Split the data into lines
        clines = []
        for c in b:

          if c in "\r\n":
            clines.append(crecvbuf)
            crecvbuf = ""

          elif c.isprintable() and len(crecvbuf)<256:
            crecvbuf += c

        # Process client requests
        for l in clines:

          # WATCHNBUIDS request
          if l == "WATCHNBUIDS":
            main_in_q.put((WATCHNBUIDS_REQUEST, (pid,)))

          # WATCHUIDS request: the requestor must be root. If not, deny the
          # request
          elif l == "WATCHUIDS":
            if uid == 0:
              main_in_q.put((WATCHUIDS_REQUEST, (pid,)))
            else:
              csendbuf = "NOAUTH"

          else:
            # WAITAUTH request: if the user is remote, ignore the username they
            # requested authentication for so the request always fails after
            # the delay they requested, to prevent remote users from logging in
            # using local credentials, yet making it looks like a legit auth
            # request process
            m = re.findall(r"^WAITAUTH\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
            if m:
              main_in_q.put((WAITAUTH_REQUEST, (pid, None if is_remote_user \
						else m[0][0], float(m[0][1]))))

            else:
              # ADDUSER request: the requestor must be root, or the same user
              # for which a new association is requested. If not, deny the
              # request
              m = re.findall(r"^ADDUSER\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)"
				r"(\s([^\s]+))?$", l)
              if m:
                if uid == 0 or m[0][0] == pw_name:
                  main_in_q.put((ADDUSER_REQUEST, (pid, m[0][0], float(m[0][1]),
						m[0][3] if m[0][3] else None)))
                else:
                  csendbuf = "NOAUTH"

              else:
                # DELUSER request: the requestor must be root, or the same user
                # as the one for which the deletion is requested. If not, deny
                # the request
                m = re.findall(r"^DELUSER\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$", l)
                if m:
                  if uid == 0 or m[0][0] == pw_name:
                    main_in_q.put((DELUSER_REQUEST, (pid, m[0][0],
							float(m[0][1]))))
                  else:
                    csendbuf = "NOAUTH"

                else:
                  # MUTEXACQ request
                  m = re.findall(r"^MUTEXACQ\s([^\s]+)\s([-+]?[0-9]+\.?[0-9]*)$",
				 l)
                  if m:
                    main_in_q.put((MUTEXACQ_REQUEST, (pid, m[0][0],
							float(m[0][1]))))

                  else:
                    # MUTEXREL request
                    m = re.findall(r"^MUTEXREL\s([^\s]+)$", l)
                    if m:
                      main_in_q.put((MUTEXREL_REQUEST, (pid, m[0])))

                    # Unknown or malformed request
                    else:
                      csendbuf = "UNKNOWN"



def is_remote_user(pid):
  """Attempt to determine if the user is logged in locally or remotely by
  tracing the parent processes and trying to find telltale process names.
  This is very poor security, and won't prevent a mildly determined bad guy
  with a local account from logging in if the PAM modules is configured as 1FA.
  But we keep it around as a last ditch effort to keep honest people honest, if
  the user has ignored the warning in the README.
  """
  pprocess = psutil.Process(pid = pid)

  while(pprocess and pprocess.name() not in remote_user_parent_process_names):
    pprocess = pprocess.parent()

  return pprocess is not None



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
    mt = os.stat(encrypted_uids_file).st_mtime
  except:
    encruids = []
    return None

  # Check if the file has changed
  if not encruids_file_mtime:
    encruids_file_mtime = mt
  else:
    if mt <= encruids_file_mtime:
      return False

  # Re-read the file
  try:
    with open(encrypted_uids_file, "r") as f:
      new_encruids = json.load(f)
  except:
    encruids = []
    return None

  # Validate and normalize the structure of the JSON format: each entry should
  # be a list of 2 or 3 strings:
  # [username, associated encrypted UID]
  #   -or-
  # [username, associated encrypted UID, associated authtok]
  # If the optional authtok is missing, add None in its place internally
  if not isinstance(new_encruids, list):
    encruids = []
    return None

  for entry in new_encruids:
    if not isinstance(entry, list):
      encruids = []
      return None
    le = len(entry)
    if not ((le == 2 and isinstance(entry[0], str) and \
		isinstance(entry[1], str)) or \
		(le == 3 and isinstance(entry[0], str) and \
		isinstance(entry[1], str) and isinstance(entry[2], str))):
      encruids = []
      return None
    if le == 2:
      entry.append(None)

  # Update the encrypted UIDs currently in memory
  encruids_file_mtime = mt
  encruids = new_encruids

  return True



def write_encruids(new_encruids):
  """Save a new set of encrypted UIDs
  """

  try:
    with open(encrypted_uids_file, "w") as f:
      json.dump([e[:2] if e[2] is None else e for e in new_encruids],
		f, indent = 2)
  except:
    return False

  return True



def encrypt(pst, key):
  """Encrypt a plaintext string into an encrypted base64 string
  """

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key = (key.encode("ascii") * 32)[:32]

  # Encrypt the string
  nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time
  es = nonce + AESGCM(key).encrypt(nonce, pst.encode("utf-8"), b"")

  # Return the encrypted text as a base64 string
  return b64encode(es).decode("ascii")



def decrypt(bes, key):
  """Decrypt an encrypted base64 string into a plaintext string
  """

  # Repeat the key to make it 32 bytes long (AES256 needs 32 bytes)
  key = (key.encode("ascii") * 32)[:32]

  try:
    es = b64decode(bes)
    return AESGCM(key).decrypt(es[:12], es[12:], b"").decode("utf-8")
  except:
    return None



def param_check(params, p, types, checker):
  """Check that the parameter p is present in the params dictionary, that it
  has one of the types in the types tuple, and that the checker function
  returns True when passed its value.
  Returns None if the parameter checks out, an error message otherwise
  """

  if p not in params:
    return 'missing parameter "{}"'.format(p)

  if type(params[p]) not in types:
    return 'parameter "{}" should be of type {}'.format(p,
		" or ".join([t.__name__ for t in types]))

  if checker is not None and not checker(params[p]):
    return 'invalid value "{}" for parameter "{}"'.format(params[p], p)

  return None



def verify_and_decrypt_authtok(uid, registered_uid_encr,
				registered_authtok_encr):
  """Function to verify that a UID matches a registered encrypted UID, then if
  so, decrypt the associated authentication token if there is one.
  This is a worker used in a multiprocessor pool to speed up authentication
  requests for users that have multiple associated UIDs, since individual
  encryption operations are quite slow
  returns (None, None) if the UID was not verified,
  (uid, None) if the UID is verified but no authentication token was given,
  (uid, authtok) if the UID is verified and the authentication token decrypted
  """

  authtok = None
  if sha512_crypt.verify(uid, registered_uid_encr):
    if registered_authtok_encr is not None:
      authtok = decrypt(registered_authtok_encr, uid)
  else:
    uid = None

  return (uid, authtok)



### Main routine
def main():
  """Main routine
  """

  setproctitle("sirfidal_server")

  # Main routine's input queue
  main_in_q = Queue()

  # Get the list of valid reader types from the list of .*_listener() functions
  # in the module
  valid_reader_types = [m[0][:-9] \
			for m in inspect.getmembers(sys.modules[__name__]) \
			if re.search("^.*_listener$", m[0])]

  # Listener-specific parameters, types and verification functions
  reader_params_check_params = {

    # USB PC/SC readers
    "pcsc":	{
      "readers_regex":	((str,), lambda v: v != ""),
      "poll_every":	((int, float), lambda v: v > 0)
    },

    # nfcpy readers
    "nfcpy":	{
      "device":		((str,), lambda v: v != ""),
      "flash_and_beep":	((bool,), None),
      "poll_every":	((int, float), lambda v: v > 0)
    },

    # Serial reader
    "serial":	{
      "device":		((str,), lambda v: v != ""),
      "baudrate":	((int,), lambda v: v > 0),
      "bytesize":	((int,), lambda v: v in (7, 8)),
      "parity":		((str,), lambda v: v in ("N", "E", "O", "M", "S")),
      "stopbits":	((int, float), lambda v: v in (1, 1.5, 2))
    },

    # Halo scanner
    "halo":	{
      "device":		((str,), lambda v: v != ""),
      "new_firmware":	((bool,), None),
      "auto_rescan":	((bool,), None),
      "alive_min_temp":	((int, float), lambda v: v >= 10),
      "alive_max_temp":	((int, float), lambda v: v <= 100),
      "alive_prefix":	((str,), lambda v: re.match("^[0-9A-F]+$", v, re.I))
    },

    # HID reader
    "hid":	{
      "device":		((str,), lambda v: v != "")
    },

    # Android device used as an NFC reader through ADB
    "android":	{
      "client":		((str,), lambda v: v != ""),
      "logcat_prefix":	((str,), lambda v: v != "")
    },

    # Proxmark3
    "proxmark3":	{
      "device":		((type(None), str), lambda v: v is None or v != ""),
      "client":		((str,), lambda v: v != ""),
      "client_workdir":	((str,), lambda v: v != ""),
      "client_timeout":	((int, float), lambda v: v > 0),
      "read_iso14443a":	((bool,), None),
      "read_iso15693":	((bool,), None),
      "read_em410x":	((bool,), None),
      "read_indala":	((bool,), None),
      "read_fdx":	((bool,), None),
      "poll_throttle":	((int, float), lambda v: v > 0)
    },

    # Chameleon Mini / Tiny
    "chameleon":	{
      "device":		((str,), lambda v: v != "")
    },

    # uFR or uFR Nano Online in slave mode
    "ufr":	{
      "device":		((str,), lambda v: v != ""),
      "poll_every":	((type(None), int, float), lambda v: v is None or v >0),
      "poll_powersave":	((bool,), None),
      "debounce_delay":	((int, float), lambda v: v > 0),
      "no_rgb1":		((list, tuple), lambda v: len(v) == 3),
      "no_rgb2_on":	((list, tuple), lambda v: len(v) == 3),
      "no_rgb2_off":	((list, tuple), lambda v: len(v) == 3),
      "conn_watchdog":	((int, float), lambda v: v > 0)
    },

    # HTTP server getting UIDs using the GET or POST method
    "http":	{
      "bind_address":	((str,), None),
      "bind_port":	((int,), lambda v: v > 0),
      "get_data_fmt":	((type(None), str), lambda v: v is None or v != ""),
      "get_reply":	((str, ), None),
      "post_data_fmt":	((type(None), str), lambda v: v is None or v != ""),
      "post_reply":	((str, ), None),
    },

    # TCP client getting UIDs from a TCP server
    "tcp":	{
      "server_address":	((str,), lambda v: v != ""),
      "server_port":	((int,), lambda v: v > 0),
      "tcp_keepalive":	((type(None), int, float), lambda v: v is None or v > 0)
    }
  }

  # Parse the list of readers in the configuration parameters, ensure the reader
  # names are valid and all the entries have valid parameters.
  # Additionally, if a reader is type "proxmark3", create a bogus working
  # directory with a "proxmark3.log" symlink pointing to /dev/null in it to
  # prevent it from logging anything
  enabled_listeners = {}

  for name in readers:

    if not name.isprintable():
      log(VERBOSITY_SILENT, "", "Error: invalid reader name {}".format(name))
      return -1

    r = param_check(readers[name], "enabled", (bool,), None)
    if r:
      log(VERBOSITY_SILENT, "", "Error: {} in declaration of reader {}"
				.format(r, name))
      return -1

    if readers[name]["enabled"]:

      r = param_check(readers[name], "type", (str,),
			lambda v: v in valid_reader_types)
      if r:
        log(VERBOSITY_SILENT, "", "Error: {} in declaration of reader {}"
				.format(r, name))
        return -1

      reader_type = readers[name]["type"]

      enabled_listeners[name] = globals()[reader_type + "_listener"]

      r = param_check(readers[name], "uids_timeout", (type(None), int, float),
			lambda v: v is None or v > 0)
      if r:
        log(VERBOSITY_SILENT, "", "Error: {} in declaration of reader {}"
				.format(r, name))
        return -1

      for p in reader_params_check_params[reader_type]:
        r = param_check(readers[name], p,
			reader_params_check_params[reader_type][p][0],
			reader_params_check_params[reader_type][p][1])
        if r:
          log(VERBOSITY_SILENT, "", "Error: {} in declaration of reader {}"
				.format(r, name))
          return -1

      if reader_type == "proxmark3":

        pm3_logfile = os.path.join(readers[name]["client_workdir"],
					"proxmark3.log")

        if os.path.exists(pm3_logfile):
          if not os.path.islink(pm3_logfile):
            log(VERBOSITY_SILENT, "", "Error: {} already exists and isn't "
					"a symlink".format(pm3_logfile))
            return -1
        else:
          try:
            os.symlink(os.devnull, pm3_logfile)
          except:
            log(VERBOSITY_SILENT, "", "Error: cannot symlink {} to {}. "
					.format(pm3_logfile, os.devnull))
            return -1

  # Set up the server's socket
  sock = socket(AF_UNIX, SOCK_STREAM)

  socklock = FileLock(socket_path + ".lock")
  try:
    with socklock.acquire(timeout = 1):
      os.unlink(socket_path)
  except Timeout:
    log(VERBOSITY_SILENT, "", "Error: socket locked")
    return -1
  except:
    pass
  finally:
    socklock.release()
  sock.bind(socket_path)

  os.chmod(socket_path, 0o666)

  sock.listen(max_server_connections)

  # Set the umask so that if we have to create the encrypted UIDs file, only
  # root can read or write to it
  os.umask(0o077)

  # Start the server
  Process(target = server, args = (main_in_q, sock,)).start()

  # Start the enabled listeners
  listener_uids_timeout = {}
  listener_active_uids_timeouts = {}

  for name in enabled_listeners:

    Process(target = enabled_listeners[name],
		args = (main_in_q, name, readers[name])).start()

    listener_uids_timeout[name] = readers[name]["uids_timeout"]
    listener_active_uids_timeouts[name] = {}

  # Main process
  active_uids = []
  active_uids_prev = []
  active_uids_update = False

  auth_cache = {}
  auth_uids_authtoks_cache = {}
  active_clients = {}

  now = time()

  while True:

    # Figure out how long we should wait for a message from another process for
    # from either the next active UID due time out, or the next active client
    # request due to expire
    timeouts = [active_clients[cpid].expires \
		for cpid in active_clients \
		if active_clients[cpid].expires is not None] + \
		[listener_active_uids_timeouts[name][uid] \
		for name in enabled_listeners \
		for uid in listener_active_uids_timeouts[name] \
		if listener_active_uids_timeouts[name][uid] is not None]
    msg_get_timeout = max(0, min(timeouts) - now) if timeouts else None

    # Get a message from another process
    try:
      msg = main_in_q.get(timeout = msg_get_timeout)
    except KeyboardInterrupt:
      return -1
    except:
      msg = None

    now = time()

    active_uids_update = False

    # Drop any active UID that has timed out from the individual listeners'
    # active UIDs
    for name in enabled_listeners:
      for uid in list(listener_active_uids_timeouts[name]):
        if listener_active_uids_timeouts[name][uid] is not None and \
		now > listener_active_uids_timeouts[name][uid]:
          del(listener_active_uids_timeouts[name][uid])
          active_uids_update = True

    # Process the message if we have one
    if msg is not None:

      log(VERBOSITY_DEBUG, "", "Received message: {}".format(msg))

      # The message is an update of the active UIDs from one of the listeners
      if msg[0] == LISTENER_UIDS_UPDATE:

        name = msg[1][0]
        uids = msg[1][1]

        # If the listener is persistent, simply take the new list of UIDs it
        # reports as the complete list of active UIDs it knows about. If it
        # has a UIDs timeout attached to it, add any new UIDs it reports and
        # refresh the associated timeouts
        if listener_uids_timeout[name] is None:
          listener_active_uids_timeouts[name] = {uid: None for uid in uids}
        else:
          for uid in uids:
            listener_active_uids_timeouts[name][uid] = now + \
						listener_uids_timeout[name]
        active_uids_update = True

      # New client notification from a client handler
      elif msg[0] == NEW_CLIENT:

        # Create this client in the list of active clients and assign it the
        # void request to time out the client if it stays idle too long
        active_clients[msg[1][0]] = client()
        active_clients[msg[1][0]].uid = msg[1][1]
        active_clients[msg[1][0]].pw_name = msg[1][2]
        active_clients[msg[1][0]].main_out_p = msg[1][3]
        active_clients[msg[1][0]].request = VOID_REQUEST
        active_clients[msg[1][0]].expires = now + \
			client_force_close_socket_timeout
        active_clients[msg[1][0]].main_out_p.send((NEW_CLIENT_ACK,))

      # The client requested that we either:
      # - authenticate a user within a certain delay (capped)
      # - associate a user / authtok with a UID and add it to the encrypted
      #   UIDs file, waiting for the new UID within a certain delay (capped)
      # - disassociate a user / authtok from a UID, waiting for the UID within
      #   a certain deiay (capped) or remove all entries for the user in the
      #   encrypted UIDs file (delay < 0)
      elif msg[0] in (WAITAUTH_REQUEST, ADDUSER_REQUEST, DELUSER_REQUEST):

        # Update this client's request in the list of active requests. Cap the
        # delay the client may request
        active_clients[msg[1][0]].request = msg[0]
        active_clients[msg[1][0]].name = msg[1][1]
        if msg[0] == ADDUSER_REQUEST:
          active_clients[msg[1][0]].authtok = msg[1][3]
        active_clients[msg[1][0]].expires = None if msg[1][2] < 0 else \
			now + (msg[1][2] if msg[1][2] <= max_auth_request_wait \
			else max_auth_request_wait)

      # The client requested to watch the evolution of the number of active
      # UIDs or the evolution of the list of UIDs themselves in real time
      elif msg[0] in (WATCHNBUIDS_REQUEST, WATCHUIDS_REQUEST):

        # Update this client's request in the list of active requests.
        # No timeout for this request: it's up to the client to close the
        # socket when it's done
        active_clients[msg[1][0]].request = msg[0]
        active_clients[msg[1][0]].name = None
        active_clients[msg[1][0]].expires = None

      # The client requested to acquire a named mutex
      elif msg[0] == MUTEXACQ_REQUEST:

        # Does the client already have a mutex with that name or too many
        # mutexes already?
        if len(active_clients[msg[1][0]].mutexes) >= max_mutexes_per_client or \
		msg[1][1] in active_clients[msg[1][0]].mutexes:

          # Send MUTEX_ERR_EXISTS to the client and replace the request with a
          # fresh void request and associated timeout
          active_clients[msg[1][0]].main_out_p.send((MUTEX_ERR_EXISTS,))
          active_clients[msg[1][0]].request = VOID_REQUEST
          active_clients[msg[1][0]].expires = now + \
			client_force_close_socket_timeout

        else:
          # Update this client's request in the list of active requests. Cap
          # the delay the client may request to acquire the mutex
          active_clients[msg[1][0]].request = msg[0]
          active_clients[msg[1][0]].name = msg[1][1]
          active_clients[msg[1][0]].expires = None if msg[1][2] < 0 else \
			now + (msg[1][2] if msg[1][2] <= max_mutex_acq_wait \
			else max_mutex_acq_wait)

      # The client requested to release a named mutex
      elif msg[0] == MUTEXREL_REQUEST:

        # Does the client have a mutex with that name?
        if msg[1][1] in active_clients[msg[1][0]].mutexes:

          # Remove the mutex from the client's set of mutexes and notify the
          # client of the success
          active_clients[msg[1][0]].mutexes -= set([msg[1][1]])
          active_clients[msg[1][0]].main_out_p.send((MUTEX_OK,))

        else:
          # Send MUTEX_ERR_NONE to the client and replace the request with a
          # fresh void request and associated timeout
          active_clients[msg[1][0]].main_out_p.send((MUTEX_ERR_NONE,))

        # Replace the request with a fresh void request and associated timeout
        active_clients[msg[1][0]].request = VOID_REQUEST
        active_clients[msg[1][0]].expires = now + \
			client_force_close_socket_timeout

      # Remove a client from the list of active clients and tell the handler
      # to stop
      elif msg[0] == CLIENT_HANDLER_STOP_REQUEST:

        del(active_clients[msg[1][0]])
        msg[1][1].send((CLIENT_HANDLER_STOP,))



    # Merge the active UIDs for all the listeners into one list of active
    # UIDs if any change has occurred to any of the individual listeners'
    # active UIDs
    if active_uids_update:

      active_uids_new = sorted(list(set([uids_translation_table[uid] \
				if uid in uids_translation_table \
				else uid for uid in \
				[uid for name in enabled_listeners \
				for uid in listener_active_uids_timeouts[name]]
				])))

      # Has the combined list of active UIDs actually changed?
      if set(active_uids_new) != set(active_uids):
        active_uids_prev = active_uids
        active_uids = active_uids_new
        active_uids_update = True
      else:
        active_uids_update = False



    # Try to reload the encrypted UIDs file. If it needed reloading, or if the
    # list of active UIDs has changed, wipe the user authentication cache
    if load_encruids() or active_uids_update:
      auth_cache = {}
      auth_uids_authtoks_cache = {}



    # Process the active clients' requests and request timeouts
    for cpid in active_clients:

      auth = False
      auth_uids_authtoks = []



      # Process active clients' requests only if we get here after getting
      # a message from another process or if the list of active UIDs has
      # changed
      if msg is not None or active_uids_update:

        # Request to watch the evolution of the number of active UIDs in
        # real-time: send an update if one is available
        if active_clients[cpid].request == WATCHNBUIDS_REQUEST and \
		(active_clients[cpid].new_request or (active_uids_update and \
		len(active_uids) != len(active_uids_prev))):
          active_clients[cpid].main_out_p.send((NBUIDS_UPDATE, \
		(len(active_uids), (len(active_uids) - len(active_uids_prev)) \
		if active_uids_update else 0)))
          active_clients[cpid].new_request = False

        # Request to watch the evolution of the list of active UIDs in
        # real-time: send an update if one is available
        if active_clients[cpid].request == WATCHUIDS_REQUEST and \
		(active_clients[cpid].new_request or (active_uids_update and \
		set(active_uids) != set(active_uids_prev))):
          active_clients[cpid].main_out_p.send((UIDS_UPDATE, (active_uids,)))
          active_clients[cpid].new_request = False

        # Authentication request
        elif active_clients[cpid].request == WAITAUTH_REQUEST and \
		active_clients[cpid].name is not None:

          # First, try to find a cached authentication status for that user...
          if active_clients[cpid].name in auth_cache:

            auth = auth_cache[active_clients[cpid].name]
            auth_uids_authtoks = auth_uids_authtoks_cache[active_clients[cpid]
							.name]

          # ...otherwise try to match all the active UIDs with the registered
          # encrypted UIDs associated with that user
          else:

            to_verify = []
            for uid in active_uids:
              for registered_user, registered_uid_encr, \
			registered_authtok_encr in encruids:
                if registered_user == active_clients[cpid].name:
                  to_verify.append((uid, registered_uid_encr,
					registered_authtok_encr))

            if to_verify:
              with Pool(processes = cpu_count()) as pool:
                for uid, authtok in pool.starmap(verify_and_decrypt_authtok,
							to_verify):
                  if uid is not None:
                    auth = True				# User authenticated...
                    auth_uids_authtoks.append((uid, authtok))	# with these UID
								# and authtok

            # Cache the result of this authentication - valid as long as the
            # list of active UIDs doesn't change and the encrypted UIDs file
            # isn't reloaded - to avoid calling doing encryption / decryption
            # each time a requesting process asks an authentication and nothing
            # has changed since the previous request
            auth_cache[active_clients[cpid].name] = auth
            auth_uids_authtoks_cache[active_clients[cpid].name] = \
							auth_uids_authtoks

        # Add user request: if we have an active UIDs update and exactly one
        # more active UID in the new list of active UIDs, associate that new
        # UID with the requested user / authtok
        elif active_clients[cpid].request == ADDUSER_REQUEST and \
		active_uids_update and \
		len(active_uids) == len(active_uids_prev) + 1:

          new_encruids = []

          # If the requestor isn't root, assume the request will be blocked
          deny_new_assoc = active_clients[cpid].uid != 0

          # Make a copy of the current encrypted UIDs file, omitting any
          # existing user/UID/authtok associations.
          # Send an error back to the client and replace the request with a
          # fresh void request and associated timeout if we find an
          # user/UID/authtok association identical to the one the client is
          # requesting.
          # If we find a existing user/UID association identical to the one the
          # client is requestion, but with a different authtok, allow the
          # operation, as normal users are allowed to modify they existing
          # registered authtok.
          new_active_uid = (set(active_uids) - set(active_uids_prev)).pop()
          for registered_user, registered_uid_encr, \
		registered_authtok_encr in encruids:
            if registered_user != active_clients[cpid].name:
              new_encruids.append([registered_user, registered_uid_encr,
					registered_authtok_encr])
            else:
              if not sha512_crypt.verify(new_active_uid, registered_uid_encr):
                new_encruids.append([registered_user, registered_uid_encr,
					registered_authtok_encr])
              else:
                if (registered_authtok_encr is None and \
			active_clients[cpid].authtok is None) or \
			(registered_authtok_encr is not None and \
			active_clients[cpid].authtok is not None and \
			decrypt(registered_authtok_encr, new_active_uid) == \
			active_clients[cpid].authtok):
                  active_clients[cpid].main_out_p.send(
						(ENCRUIDS_UPDATE_ERR_EXISTS,))
                  active_clients[cpid].request = VOID_REQUEST
                  active_clients[cpid].expires = now + \
					client_force_close_socket_timeout
                  break;
                else:
                  if active_clients[cpid].pw_name == active_clients[cpid].name:
                    deny_new_assoc = False

          # If no existing user/UID association was found in the existing
          # encrypted UIDs file and the requestor isn't root, send the client an
          # authorization error and replace the request with a fresh void
          # request and associated timeout
          if deny_new_assoc:
            active_clients[cpid].main_out_p.send((AUTH_RESULT,
							(AUTH_NOK, None)))
            active_clients[cpid].request = VOID_REQUEST
            active_clients[cpid].expires = now + \
					client_force_close_socket_timeout

          # Encrypt the UID and the authtok, associate then with the user,
          # write the new encrypted UIDs file, then replace the request
          # with a fresh void request and associated timeout
          if active_clients[cpid].request != VOID_REQUEST:
            authtok_encr = encrypt(active_clients[cpid].authtok,
				new_active_uid) \
				if active_clients[cpid].authtok is not None \
				else None
            new_encruids.append([active_clients[cpid].name,
					sha512_crypt.hash(new_active_uid),
					authtok_encr])
            if write_encruids(new_encruids):
              active_clients[cpid].main_out_p.send((ENCRUIDS_UPDATE_OK,))
            else:
              active_clients[cpid].main_out_p.send((ENCRUIDS_UPDATE_ERR_WRITE,))
            active_clients[cpid].request = VOID_REQUEST
            active_clients[cpid].expires = now + \
			client_force_close_socket_timeout

        # Delete user request: if we have an active UIDs update and exactly one
        # more active UID in the new list of active UIDs, disassociate
        # any matching user/UID - unless we have no timeout, in which case
        # remove all associations matching the requested user
        elif active_clients[cpid].request == DELUSER_REQUEST and \
		(active_clients[cpid].expires is None or (
		active_uids_update and \
		len(active_uids) == len(active_uids_prev) + 1)):

          new_encruids = []

          # Find one or more existing matching user/UID associations and remove
          # them if needed
          assoc_deleted = False
          new_active_uid = (set(active_uids) - set(active_uids_prev)).pop() \
				if active_uids_update else ""
          for registered_user, registered_uid_encr, \
		registered_authtok_encr in encruids:
            if registered_user == active_clients[cpid].name and (
			active_clients[cpid].expires is None or \
			sha512_crypt.verify(new_active_uid,
						registered_uid_encr)):
              assoc_deleted = True
            else:
              new_encruids.append([registered_user, registered_uid_encr,
					registered_authtok_encr])

          # If we found one or more associations to delete, write the new
          # encrypted UIDs file. Otherwise notify the client. Then replace the
          # request with a fresh void request and associated timeout
          if assoc_deleted:
            if write_encruids(new_encruids):
              active_clients[cpid].main_out_p.send((ENCRUIDS_UPDATE_OK,))
            else:
              active_clients[cpid].main_out_p.send((ENCRUIDS_UPDATE_ERR_WRITE,))
          else:
            active_clients[cpid].main_out_p.send((ENCRUIDS_UPDATE_ERR_NONE,))

          active_clients[cpid].request = VOID_REQUEST
          active_clients[cpid].expires = now + client_force_close_socket_timeout

        # Named mutex acquisition: check that the requested mutex name isn't
        # used by any other client. If it is free to use, assign it to this
        # client, notify the client then replace the request with a
        # fresh void request and associated timeout
        elif active_clients[cpid].request == MUTEXACQ_REQUEST:

          if active_clients[cpid].name not in [m for cpid in active_clients \
					for m in active_clients[cpid].mutexes]:
            active_clients[cpid].mutexes.add(active_clients[cpid].name)
            active_clients[cpid].main_out_p.send((MUTEX_OK,))
            active_clients[cpid].request = VOID_REQUEST
            active_clients[cpid].expires = now + \
			client_force_close_socket_timeout



      # Process request timeouts:

      # If an authentication request has timed out or the authentication is
      # successful, notify the client and replace the request with a fresh void
      # request and associated timeout. If the requestor is root or the same
      # user they request an authentication for, they're allowed to know the
      # authenticating UID(s), so send them along. If the requestor is root
      # only, they also have the right to get the authtoks.
      if active_clients[cpid].request == WAITAUTH_REQUEST and \
		(auth or active_clients[cpid].expires is None or \
		now >= active_clients[cpid].expires):
        if auth:
          if active_clients[cpid].uid == 0:
            utl = [uid if authtok is None else "{}:{}".format(uid, authtok) \
			for uid, authtok in auth_uids_authtoks]
          elif active_clients[cpid].name == active_clients[cpid].pw_name:
            utl = [uid for uid, _ in auth_uids_authtoks]
          active_clients[cpid].main_out_p.send((AUTH_RESULT, (AUTH_OK, utl)))
        else:
          active_clients[cpid].main_out_p.send((AUTH_RESULT, (AUTH_NOK, None)))
        active_clients[cpid].request = VOID_REQUEST
        active_clients[cpid].expires = now + client_force_close_socket_timeout

      # If an ADDUSER or DELUSER request has timed out, notify the client and
      # replace the request with a fresh void request and associated timeout
      if (active_clients[cpid].request == ADDUSER_REQUEST or \
		active_clients[cpid].request == DELUSER_REQUEST) and \
		(active_clients[cpid].expires is None or \
		now >= active_clients[cpid].expires):
        active_clients[cpid].main_out_p.send((ENCRUIDS_UPDATE_ERR_TIMEOUT,))
        active_clients[cpid].request = VOID_REQUEST
        active_clients[cpid].expires = now + client_force_close_socket_timeout

      # If a named mutex acquisition request has timed out, it means a mutex of
      # that name is held by another client and wasn't released in time to be
      # assigned to this client. Notify the client handler then replace the
      # request with a fresh void request and associated timeout
      if active_clients[cpid].request == MUTEXACQ_REQUEST and \
		(active_clients[cpid].expires is None or \
		now >= active_clients[cpid].expires):
        active_clients[cpid].main_out_p.send((MUTEX_ERR_EXISTS,))
        active_clients[cpid].request = VOID_REQUEST
        active_clients[cpid].expires = now + client_force_close_socket_timeout

      # if a void request request has timed out, notify the client handler
      # and clear the request
      elif active_clients[cpid].request == VOID_REQUEST and \
		now >= active_clients[cpid].expires:
        active_clients[cpid].main_out_p.send((VOID_REQUEST_TIMEOUT,))
        active_clients[cpid].request = None



### Jump to the main routine
if __name__ == "__main__":

  # Parse the command line arguments
  argparser = argparse.ArgumentParser()

  mutexargs = argparser.add_mutually_exclusive_group()

  mutexargs.add_argument(
	"-s", "--silent",
	help = "Only output fatal error messages",
	action = "store_true")

  mutexargs.add_argument(
	"-d", "--debug",
	help = "Output extended debug messages",
	action = "store_true")

  args = argparser.parse_args()

  if args.silent:
    verbosity = VERBOSITY_SILENT

  elif args.debug:
    verbosity = VERBOSITY_DEBUG

  sys.exit(main())
