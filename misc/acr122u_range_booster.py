#!/usr/bin/python3
"""Set the RF configuration of an ACR122U NFC reader with the maximum Rx gain
possible (48 dB) to increase the read range. Especially useful with small NFC
tags and implants that have smaller antennae.

This script requires PC/SC lite (pcscd daemon running) and the CCID exchange
command allowed (ifdDriverOptions set to 0x0001 in /etc/libccid_Info.plist).
It also requires the Python pyscard module.
"""

### Parameters
new_rx_gain = 0x7    # 48 dB



### Modules
from smartcard.scard import *



### Defines
# Default PN532 RF configuration values
CfgItem_0x0A_CIU_RFCfg = 0x59
CfgItem_0x0A_CIU_GsNOn = 0xf4
CfgItem_0x0A_CIU_CWGsP = 0x3f
CfgItem_0x0A_CIU_ModGsP = 0x11
CfgItem_0x0A_CIU_Demod_when_own_RF_is_On = 0x4d
CfgItem_0x0A_CIU_RxThreshold = 0x85
CfgItem_0x0A_CIU_Demod_when_own_RF_is_Off = 0x61
CfgItem_0x0A_CIU_GsNOff = 0x6f
CfgItem_0x0A_CIU_ModWidth = 0x26
CfgItem_0x0A_CIU_MifNFC = 0x62
CfgItem_0x0A_CIU_TxBitPhase = 0x87

CfgItem_0x0B_CIU_RFCfg = 0x69
CfgItem_0x0B_CIU_GsNOn = 0xff
CfgItem_0x0B_CIU_CWGsP = 0x3f
CfgItem_0x0B_CIU_ModGsP = 0x11
CfgItem_0x0B_CIU_Demod_when_own_RF_is_On = 0x41
CfgItem_0x0B_CIU_RxThreshold = 0x85
CfgItem_0x0B_CIU_Demod_when_own_RF_is_Off = 0x61
CfgItem_0x0B_CIU_GsNOff = 0x6f

# CCID escape command
ioctl_ccid_escape = SCARD_CTL_CODE(1)	# For PCSC-Lite. Use 3500 for Windows

# ACR122U pseudo-APDU commands
cmd_get_fw_revision = [0xff, 0x00, 0x48, 0x00, 0x00]

# PN53x commands, wrapped in ACR122U direct transmit pseudo-APDUs
cmd_set_rfconf_0x0a = [0xff, 0x00, 0x00, 0x00, 0x0e, 0xd4, 0x32, 0x0a,
			CfgItem_0x0A_CIU_RFCfg,
			CfgItem_0x0A_CIU_GsNOn,
			CfgItem_0x0A_CIU_CWGsP,
			CfgItem_0x0A_CIU_ModGsP,
			CfgItem_0x0A_CIU_Demod_when_own_RF_is_On,
			CfgItem_0x0A_CIU_RxThreshold,
			CfgItem_0x0A_CIU_Demod_when_own_RF_is_Off,
			CfgItem_0x0A_CIU_GsNOff,
			CfgItem_0x0A_CIU_ModWidth,
			CfgItem_0x0A_CIU_MifNFC,
			CfgItem_0x0A_CIU_TxBitPhase]

cmd_set_rfconf_0x0b = [0xff, 0x00, 0x00, 0x00, 0x0b, 0xd4, 0x32, 0x0b,
			CfgItem_0x0B_CIU_RFCfg,
			CfgItem_0x0B_CIU_GsNOn,
			CfgItem_0x0B_CIU_CWGsP,
			CfgItem_0x0B_CIU_ModGsP,
			CfgItem_0x0B_CIU_Demod_when_own_RF_is_On,
			CfgItem_0x0B_CIU_RxThreshold,
			CfgItem_0x0B_CIU_Demod_when_own_RF_is_Off,
			CfgItem_0x0B_CIU_GsNOff]



### Routines
def send_acr122u_control_command(cmd, hcard):
  """Send the ACR122U a control command, return the raw result and raise an
  exception in case of error
  """
  hresult, response = SCardControl(hcard, ioctl_ccid_escape, cmd)
  if hresult != SCARD_S_SUCCESS:
     raise SystemError("Failure to control: {}".format(
			SCardGetErrorMessage(hresult)))
  return(response)
  


### Main routine
def main():
  """Main routine
  """

  # Establish context and connect to the ACR122U
  try:
    hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
    hresult, hcard, dwActiveProtocol = SCardConnect(hcontext,
					'ACS ACR122U PICC Interface 00 00',
					SCARD_SHARE_DIRECT, SCARD_PROTOCOL_T0)
  except:
    print("Cannot connect to ACR122U")
    return(-1)

  # Get the ACR122U's firmware revision number, to test that CCID escape has
  # been enabled and to double-check that the reader is indeed an ACR122U
  try:
    fwrev = "".join([chr(v) for v in send_acr122u_control_command(
		cmd_get_fw_revision, hcard)])
  except Exception as e:
    print(e)
    print("Error getting ACR122U firmware revision number.")
    print("Is the CCID exchange command allowed in /etc/libccid_Info.plist")
    return(-2)
  
  if fwrev[:7].upper() != "ACR122U":
    print('Error: "{}" does not appear to be an ACR122U'.format(fwrev))
    return(-3)

  # Set the RF configuration parameters with the new Rx gain
  cmd_set_rfconf_0x0a[8] = (cmd_set_rfconf_0x0a[8] & 0x8f) | (new_rx_gain << 4)
  cmd_set_rfconf_0x0b[8] = (cmd_set_rfconf_0x0a[8] & 0x8f) | (new_rx_gain << 4)

  try:
    send_acr122u_control_command(cmd_set_rfconf_0x0a, hcard)
  except:
    print("Error setting RFConfiguration CfgItem 0x0A")
    return(-4)

  try:
    send_acr122u_control_command(cmd_set_rfconf_0x0b, hcard)
  except:
    print("Error setting RFConfiguration CfgItem 0x0B")
    return(-4)

  # Inform the user
  print("ACR122U Rx gain set to 0x{:01X}".format(new_rx_gain))

      

### Jump to the main routine
if __name__ == "__main__":
  exit(main())
