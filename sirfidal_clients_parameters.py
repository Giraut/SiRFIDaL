### Configuration parameters for the SiRFIDaL clients
###
### Each client has a dedicated set of parameters in the sirfidal_clients_params
### dictionary. The values are loaded from /etc/sirfidal_clients_parameters.py
### first, then loaded again if possible from ~/.sirfidal_clients_parameters.py.
### If the latter file is present, whatever parameter it holds override the
### corresponding parameters in the global file.

sirfidal_clients_params = {

  # Parameters for sirfidal_autolockscreen.py
  "sirfidal_autolockscreen":	{
    "screen_locker_lock_command":	"cinnamon-screensaver-command -l",
    "screen_locker_unlock_command":	"cinnamon-screensaver-command -d",
    "screen_locker_query_command":	"cinnamon-screensaver-command -q",
    "screen_locker_query_locked_regex":	"is active",

    "default_lock_timeout":		3, #s
    "default_unlock_timeout":		0, #s
    "default_do_authpersistent":	False,
    "default_do_verbose":		False,

    "check_user_auth_every":		0.2, #s
    "check_session_lock_status_every":	5 #s
  },

  # Parameters for sirfidal_autotype.py
  "sirfidal_autotype":		{
    "default_definitions_file":		"~/.sirfidal_autotype_definitions"
  },

  # Parameters for sirfidal_beep.py
  "sirfidal_beep":		{
    "default_up_sound_file":	"/usr/local/share/sounds/sirfidal/up.wav",
    "default_down_sound_file":	"/usr/local/share/sounds/sirfidal/down.wav",

    "use_external_player":	True,	# Set this to use an external player
					# instead of the pyaudio module to play
					# WAV files
    "force_restart_pulseaudio":	False,	# Enable this to (re)start a Pulseaudio
					# daemon before playing a WAV file

    # Full path to the external player if use_external_player is set
    "external_player_command":	"/usr/bin/play {sndfile}",

    # Full path to the pulseaudio executable if force_restart_pulseaudio is set
    "pulseaudio_command":	"/usr/bin/pulseaudio"
  },
}
