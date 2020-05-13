-- Script to read UIDs and print them repeatedly with a prefix.
-- For use with the SiRFIDaL server, to turn the Proxmark3 into a "dumb"
-- repeating serial reader, using the proxmark3 client as a backend.
-- Only handles ISO 14443 type A transponders for now.
local cmds = require('commands')
local timeout = 200
local uid, uidlen
local ISO14A_CONNECT = 1
local ISO14A_NO_RATS = 0x200
local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a,
  			arg1 = ISO14A_CONNECT + ISO14A_NO_RATS}
while not core.SendCommand(command:getBytes()) do
  uid=""
  local response = core.WaitForResponseTimeout(cmds.CMD_ACK, timeout)
  if response then
    local count, _, arg0 = bin.unpack('LLLL', response)
    if arg0 ~= 0 then
      _, uid, uidlen = bin.unpack('H10C', string.sub(response, count))
      uid = uid:sub(1, 2 * uidlen)
    end
  end
  print(("uid:%s"):format(uid))
end
