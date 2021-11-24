### Configuration parameters for the SiRFIDaL server

# List of readers managed by the server, and associated parameters
readers = {

  # USB PC/SC readers
  "pcsc_readers":	{
    "enabled":		True,
    "type":		"pcsc",
    "uids_timeout":	None, # as PC/SC readers are polled
    "poll_every":	0.2 #s
  },

  # Serial reader
  "serial_reader_#1":	{
    "enabled":		False,
    "type":		"serial",
    "uids_timeout":	1, #s
    "device":		"/dev/ttyUSB0",
    "baudrate":		9600,
    "bytesize":		8,
    "parity":		"N",
    "stopbits":		1
  },

  # Halo scanner
  "halo_scanner_#1":	{
    "enabled":		False,
    "type":		"halo",
    "uids_timeout":	1, #s
    "device":		"/dev/ttyACM0",
    "new_firmware":	True
  },

  # HID reader
  "keyboard_wedge_#1":	{
    "enabled":		False,
    "type":		"hid",
    "uids_timeout":	1, #s
    "device":           "/dev/input/by-id/"
				"usb-ACS_ACR1281_Dual_Reader-if01-event-kbd"
  },

  # Android device used as an NFC reader through ADB
  "android_device_#1":	{
    "enabled":		False,
    "type":		"android",
    "uids_timeout":	None, #s for one-shot mode, None for persistent mode
    "client":		"/usr/bin/adb",
    "logcat_prefix":	"nfcuid:"
  },

  # Proxmark3
  "proxmark3_#1":	{
    "enabled":		False,
    "type":		"proxmark3",
    "uids_timeout":	None, # as the PM3 reader is polled
    "device":		"/dev/ttyACM0",	# None if pm3 script is used as client
    "client":		"/usr/local/bin/proxmark3",
    "client_workdir":	"/tmp",
    "client_timeout":	2, #s
    "read_iso14443a":	True,
    "read_iso15693":	False,
    "read_em410x":	False,
    "read_indala":	False,
    "read_fdx":		False,
    "poll_throttle":	0.5 #s
  },

  # Chameleon Mini / Tiny
  "chameleon_#1":	{
    "enabled":		False,
    "type":		"chameleon",
    "uids_timeout":	1, #s
    "device":		"/dev/ttyACM1",
  },

  # uFR or uFR Nano Online in slave mode
  "ufr_nano_#1":	{
    "enabled":		False,
    "type":		"ufr",
    "uids_timeout":	None, # as the uFR reader is polled or asynchronous
    "device":		"tcp://ufr:8881",
    "poll_every":	None, #s for polled mode, None for asynchronous mode
    "poll_powersave":	True,	# uFR firmware > v5.0.51 required
    "debounce_delay":	0.2, #s
    "no_rgb1":		(255, 160, 0),	# Nano Online, LED1 color
    "no_rgb2_on":	(0, 160, 0),	# Nano Online, LED2 color if tag present
    "no_rgb2_off":	(160, 0, 0),	# Nano Online, LED2 color if no tag
    "conn_watchdog":	10 #s - Only in asynchronous ID sending mode
  },

  # HTTP server getting UIDs using the GET or POST method
  "http_server_#1":	{
    "enabled":		False,
    "type":		"http",
    "uids_timeout":	1, #s
    "bind_address":	"",
    "bind_port":	30080,
    "get_data_fmt":	"^.*data=%02([0-9A-F]+)%0D%0A%03$", # None disables GET
    "get_reply":	"OK",
    "post_data_fmt":	"^.*UID=([0-9a-fA-F:]+).*$", # None disables POST
    "post_reply":	""
  },

  # TCP client getting UIDs from a TCP server
  "tcp_client_#1":	{
    "enabled":		False,
    "type":		"tcp",
    "uids_timeout":	1, #s
    "server_address":	"localhost",
    "server_port":	8080,
    "tcp_keepalive":	5 #s - None to disable
  }
}

# Server parameters
socket_path = "/tmp/sirfidal_server.socket"
max_server_connections = 15
max_auth_request_wait = 60 #s
client_force_close_socket_timeout = 60 #s

# Encrypted UIDs file path
encrypted_uids_file = "/etc/sirfidal_encr_uids"

# Optional UID translation table for special UIDs: any UID in the keys of this
# dictionary will be translated internally into the corresponding value, as if
# the reader had read the value in the first place. Useful for special tags
# that report two UIDs
uids_translation_table = {}

# Names of disallowed parent process names for requesting processes. This is a
# very weak security check, but we leave it there just in case
remote_user_parent_process_names = ("sshd", "telnetd")
