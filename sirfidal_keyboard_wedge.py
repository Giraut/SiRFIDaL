#!/usr/bin/python3
"""Utility to emulate a keyboard wedge-type RFID / NFC reader and send UIDs
read by the SiRFIDaL server as characters "typed" by a keyboard.

Without arguments, the program "types out" the UIDs read by the SiRFIDaL server
indefinitely, one per line, like a real keyboard wedge would, until the user
hits CTRL-C. Unlike a real keyboard wedge however, the program loads the local
keyboard layout and adapts the sequence of keystrokes it "types" to yield the
correct characters for non-US users. If you would like to emulate a real
keyboard wedge strictly instead, you can force the program to use the US
keyboard layout regardless of the locale with the -u / --uskbd argument.

It is also possible to modify the output format with the -p / --prefix and
-s / --suffix arguments.

Sample use cases with the optional arguments:

- All UIDs on one line, separated by spaces:

    sirfidal_keyboard_wedge.py -s ' '

- "UID=" before the value, semicolon after the value, one per line:

    sirfidal_keyboard_wedge.py -p UID= -s $';\n'

This program is a SiRFIDaL client. It requires the SiRFIDaL server to read the
UIDs of RFID / NFC transponders.

THIS SCRIPT MUST BE RUN AS ROOT!
"""

### Modules
import re
import sys
import argparse
from time import sleep
from evdev import UInput, ecodes as e
from subprocess import Popen, PIPE, DEVNULL
import sirfidal_client_class as scc



### Defines
# Key states
KEY_UP = 0
KEY_DN = 1

# Shift modifiers masks
LS = 0x01000
RS = 0x02000
S  = LS

# Ctrl modifiers masks
LC = 0x04000
RC = 0x08000
C  = LC

# Alt modifier mask
A = 0x10000

# AltGr modifier mask
AGR = 0x20000

# Dead key mask
DEADKEY = 0x40000

# Keycode field mask
KC = 0X00fff

# Special characters
BS  = "\b"
TAB = "\t"
CR  = "\r"
ESC = "\x1b"
DEL = "\x7f"

# Default ASCII to event codes table for the US keyboard layout
ascii_to_ecodes_us = {
  BS  : e.KEY_BACKSPACE,    TAB : e.KEY_TAB,          CR  : e.KEY_ENTER,
  ESC : e.KEY_ESC,          " " : e.KEY_SPACE,        "!" : S|e.KEY_1,
  '"' : S|e.KEY_APOSTROPHE, "#" : S|e.KEY_3,          "$" : S|e.KEY_4,
  "%" : S|e.KEY_5,          "&" : S|e.KEY_7,          "'" : e.KEY_APOSTROPHE,
  "(" : S|e.KEY_9,          ")" : S|e.KEY_0,          "*" : S|e.KEY_8,
  "+" : S|e.KEY_EQUAL,      "," : e.KEY_COMMA,        "-" : e.KEY_MINUS,
  "." : e.KEY_DOT,          "/" : e.KEY_SLASH,        "0" : e.KEY_0,
  "1" : e.KEY_1,            "2" : e.KEY_2,            "3" : e.KEY_3,
  "4" : e.KEY_4,            "5" : e.KEY_5,            "6" : e.KEY_6,
  "7" : e.KEY_7,            "8" : e.KEY_8,            "9" : e.KEY_9,
  ":" : S|e.KEY_SEMICOLON,  ";" : e.KEY_SEMICOLON,    "<" : S|e.KEY_COMMA,
  "=" : e.KEY_EQUAL,        ">" : S|e.KEY_DOT,        "?" : S|e.KEY_SLASH,
  "@" : S|e.KEY_2,          "A" : S|e.KEY_A,          "B" : S|e.KEY_B,
  "C" : S|e.KEY_C,          "D" : S|e.KEY_D,          "E" : S|e.KEY_E,
  "F" : S|e.KEY_F,          "G" : S|e.KEY_G,          "H" : S|e.KEY_H,
  "I" : S|e.KEY_I,          "J" : S|e.KEY_J,          "K" : S|e.KEY_K,
  "L" : S|e.KEY_L,          "M" : S|e.KEY_M,          "N" : S|e.KEY_N,
  "O" : S|e.KEY_O,          "P" : S|e.KEY_P,          "Q" : S|e.KEY_Q,
  "R" : S|e.KEY_R,          "S" : S|e.KEY_S,          "T" : S|e.KEY_T,
  "U" : S|e.KEY_U,          "V" : S|e.KEY_V,          "W" : S|e.KEY_W,
  "X" : S|e.KEY_X,          "Y" : S|e.KEY_Y,          "Z" : S|e.KEY_Z,
  "[" : e.KEY_LEFTBRACE,    "\\": e.KEY_BACKSLASH,    "]" : e.KEY_RIGHTBRACE,
  "^" : S|e.KEY_6,          "_" : S|e.KEY_MINUS,      "`" : e.KEY_GRAVE,
  "a" : e.KEY_A,            "b" : e.KEY_B,            "c" : e.KEY_C,
  "d" : e.KEY_D,            "e" : e.KEY_E,            "f" : e.KEY_F,
  "g" : e.KEY_G,            "h" : e.KEY_H,            "i" : e.KEY_I,
  "j" : e.KEY_J,            "k" : e.KEY_K,            "l" : e.KEY_L,
  "m" : e.KEY_M,            "n" : e.KEY_N,            "o" : e.KEY_O,
  "p" : e.KEY_P,            "q" : e.KEY_Q,            "r" : e.KEY_R,
  "s" : e.KEY_S,            "t" : e.KEY_T,            "u" : e.KEY_U,
  "v" : e.KEY_V,            "w" : e.KEY_W,            "x" : e.KEY_X,
  "y" : e.KEY_Y,            "z" : e.KEY_Z,            "{" : S|e.KEY_LEFTBRACE,
  "|" : S|e.KEY_BACKSLASH,  "}" : S|e.KEY_RIGHTBRACE, "~" : S|e.KEY_GRAVE,
  DEL : e.KEY_DELETE
}

# Modifiers to event codes
modifiers_to_ecodes = {
  LS:  e.KEY_LEFTSHIFT,  RS:  e.KEY_RIGHTSHIFT, LC:  e.KEY_LEFTCTRL,
  RC:  e.KEY_RIGHTCTRL,  A:   e.KEY_LEFTALT,    AGR: e.KEY_RIGHTALT
}

# Dumpkeys names to ASCII
dumpkeys_to_ascii = {
  "Delete"      : BS,       "Tab"         : TAB,      "Return"      : CR,
  "Escape"      : ESC,      "space"       : " ",      "exclam"      : "!",
  "quotedbl"    : '"',      "numbersign"  : "#",      "dollar"      : "$",
  "percent"     : "%",      "ampersand"   : "&",      "apostrophe"  : "'",
  "parenleft"   : "(",      "parenright"  : ")",      "asterisk"    : "*",
  "plus"        : "+",      "comma"       : ",",      "minus"       : "-",
  "period"      : ".",      "slash"       : "/",      "zero"        : "0",
  "one"         : "1",      "two"         : "2",      "three"       : "3",
  "four"        : "4",      "five"        : "5",      "six"         : "6",
  "seven"       : "7",      "eight"       : "8",      "nine"        : "9",
  "colon"       : ":",      "semicolon"   : ";",      "less"        : "<",
  "equal"       : "=",      "greater"     : ">",      "question"    : "?",
  "at"          : "@",      "A"           : "A",      "B"           : "B",
  "C"           : "C",      "D"           : "D",      "E"           : "E",
  "F"           : "F",      "G"           : "G",      "H"           : "H",
  "I"           : "I",      "J"           : "J",      "K"           : "K",
  "L"           : "L",      "M"           : "M",      "N"           : "N",
  "O"           : "O",      "P"           : "P",      "Q"           : "Q",
  "R"           : "R",      "S"           : "S",      "T"           : "T",
  "U"           : "U",      "V"           : "V",      "W"           : "W",
  "X"           : "X",      "Y"           : "Y",      "Z"           : "Z",
  "bracketleft" : "[",      "backslash"   : "\\",     "bracketright": "]",
  "asciicircum" : "^",      "underscore"  : "_",      "grave"       : "`",
  "a"           : "a",      "b"           : "b",      "c"           : "c",
  "d"           : "d",      "e"           : "e",      "f"           : "f",
  "g"           : "g",      "h"           : "h",      "i"           : "i",
  "j"           : "j",      "k"           : "k",      "l"           : "l",
  "m"           : "m",      "n"           : "n",      "o"           : "o",
  "p"           : "p",      "q"           : "q",      "r"           : "r",
  "s"           : "s",      "t"           : "t",      "u"           : "u",
  "v"           : "v",      "w"           : "w",      "x"           : "x",
  "y"           : "y",      "z"           : "z",      "braceleft"   : "{",
  "bar"         : "|",      "braceright"  : "}",      "asciitilde"  : "~",
  "Remove"      : DEL,
  # Dead keys
  "dead_circumflex": "^",
  "dead_grave"     : "`",
  "dead_tilde"     : "~"
}

# Dumpkeys names to modifiers masks
dumpkeys_modifiers_to_masks = {
  "plain"  : 0,  "shift"  : S,  "shiftl" : LS, "shiftr" : RS, "control": C,
  "ctrll"  : LC, "ctrlr"  : LC, "alt"    : A,   "altgr" : AGR
}



### Routines
def load_local_keymap():

  ascii_to_ecodes = {}

  # Run dumpkeys, capture its output (simpler and more portable than doing it
  # ourselves)
  dkout = Popen(["dumpkeys", "-1"], stdout = PIPE, stderr = DEVNULL).\
		communicate()[0].decode("utf-8").split("\n")

  # Process the lines from dumpkeys
  for l in dkout:

    fields = l.split()

    # Modifiers / keycodes definition
    if len(fields) >= 5 and fields[-4] == "keycode" and \
	re.match("^[0-9]+$", fields[-3]) and fields[-2] == "=" and \
	fields[-1].lstrip("+") in dumpkeys_to_ascii.keys():

      # Get the dumpkeys name
      dn = dumpkeys_to_ascii[fields[-1].lstrip("+")]

      newdef = int(fields[-3])

      if fields[-1][:5] == "dead_":
        newdef |= DEADKEY

      # Compile the modifiers. Drop the new definitions if we find any modifier
      # we don't know about
      for m in fields[:-3]:
        if m not in dumpkeys_modifiers_to_masks:
          newdefs = None
          break
        else:
          newdef |= dumpkeys_modifiers_to_masks[m]

      # "Adopt" the new definition if it doesn't require more modifiers than
      # the previous one
      if newdef is not None and (dn not in ascii_to_ecodes or \
				ascii_to_ecodes[dn] > newdef):
        ascii_to_ecodes[dn] = newdef

  # Complete any holes left in the local keymap with definitions from the
  # default US keymap
  for d in set(ascii_to_ecodes_us) - set(ascii_to_ecodes):
    ascii_to_ecodes[d]=ascii_to_ecodes_us[d]

  return(ascii_to_ecodes)



### Main routine
def main():
  """Main routine
  """

  # Read the command line arguments
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-p", "--prefix",
	type = str,
	help = "UIDs output prefix to type (default: none)",
	default = "",
	required = False)

  argparser.add_argument(
	"-s", "--suffix",
	type = str,
	help = "UIDs output suffix to type (default: carriage return)",
	default = "\r",
	required = False)

  argparser.add_argument(
	"-u", "--uskbd",
	action = "store_true",
	help = "Use the default US keyboard layout instead of the local layout",
	required = False)

  args = argparser.parse_args()

  prefix = re.sub("\n", "\r", args.prefix)
  suffix = re.sub("\n", "\r", args.suffix)

  # Load the current keymap
  ascii_to_ecodes = ascii_to_ecodes_us
  if not args.uskbd:
    try:
      ascii_to_ecodes = load_local_keymap()
    except:
      print("Warning: cannot load the current keyboard layout: "
		"defaulting to the US layout")

  # Open uinput device
  try:
    ui = UInput()
  except:
    print("UInput open error: are you root?")
    return -1

  uids_list = None

  while True:

    try:

      # Connect to the server
      with scc.sirfidal_client() as sc:

        # Watch UIDs
        for r, uids in sc.watchuids():

          # The server informs us we're not authorized to watch UIDs
          if r == scc.NOAUTH:
            print("Not authorized! Are you root?")
            ui.close()
            return -1

          # If we got the initial UIDs update, initialize the UIDs lists
          if uids_list is None:
            uids_list = uids

          uids_list_prev = uids_list
          uids_list = uids

          # "Type out" the new UIDs
          ui_write_err = False

          for uid in set(uids_list) - set(uids_list_prev):
            for c in prefix + uid + suffix:

              ecode = ascii_to_ecodes.get(c, None)

              # Compose the modifiers key-down / key-up sequences
              modseq_keydn = []
              modseq_keyup = []
              for m in modifiers_to_ecodes:
                if ecode & m:
                  modseq_keydn += [[modifiers_to_ecodes[m], KEY_DN]]
                  modseq_keyup = [[modifiers_to_ecodes[m], KEY_UP]] + \
					modseq_keyup

              # Compose the key's key-down / key-up sequence
              keyseq = [[ecode & KC, KEY_DN]]
              keyseq += [[ecode & KC, KEY_UP]]
              if ecode & DEADKEY:
                keyseq += [[e.KEY_SPACE, KEY_DN]]
                keyseq += [[e.KEY_SPACE & KC, KEY_UP]]

              # "Type" the complete sequence
              try:

                for key, state in modseq_keydn + keyseq + modseq_keyup:
                  ui.write(e.EV_KEY, key, state)

                ui.syn()

              except Exception as exc:
                print("UInput write error: {}".format(exc))
                ui_write_err = True
                break

            if ui_write_err:
              break

    except KeyboardInterrupt:
      ui.close()
      return 0

    except:
      uids_list = None
      sleep(1)	# Wait a bit before reconnecting in case of error or timeout



### Jump to the main routine
if __name__=="__main__":
  sys.exit(main())
