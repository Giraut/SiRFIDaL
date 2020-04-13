#!/usr/bin/python3
"""Script to show UIDs read by the SiRFIDaL server as they are being read.
THIS SCRIPT MUST BE RUN AS ROOT!
"""

### Parameters
socket_path="/tmp/sirfidal_server.socket"



### Modules
import re
import sys
from time import sleep
from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET, SO_PASSCRED



### Main routine
def main():
  """Main routine
  """

  uids_list=[]

  sock=None

  while True:

    if not sock:

      # Open a socket to the auth server
      try:
        sock=socket(AF_UNIX, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        sock.connect(socket_path)
      except:
        if sock:
          sock.close()
        sock=None
        try:
          sleep(1)
        except:
          return(0)
        continue

      # Send the request to the server
      try:
        sock.sendall("WATCHUIDS\n".encode("ascii"))
      except:
        sock.close()
        sock=None
        try:
          sleep(1)
        except:
          return(0)
        continue
 
      crecvbuf=""

    clines=[]

    # Get data from the socket
    try:
      b=sock.recv(256).decode("ascii")
    except KeyboardInterrupt:
      sock.close()
      return(0)
    except:
      sock.close()
      sock=None
      try:
        sleep(1)
      except:
        return(0)
      continue

    # If we got nothing, the server has closed its end of the socket.
    if len(b)==0:
      sock.close()
      sock=None
      try:
        sleep(1)
      except:
        return(0)
      continue

    # Read CR- or LF-terminated lines
    for c in b:

      if c=="\n" or c=="\r":
        clines.append(crecvbuf)
        crecvbuf=""

      elif len(crecvbuf)<256 and c.isprintable():
        crecvbuf+=c

    # Process the lines
    for l in clines:

      # Denied authorization
      if l=="NOAUTH":

        print("Not authorized! Are you root?")
        sock.close()
        return(-1)

      # Active UIDs list updates
      elif(re.match("^UIDS(\s[^\s]+)*$", l)):

        last_uids_list=uids_list
        uids_list=sorted(l.split()[1:])

        if not uids_list and not last_uids_list:
          print("Waiting for UIDs - CTRL-C to quit...")

        else:
          for uid in set(uids_list) - set(last_uids_list):
            print(uid)



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
