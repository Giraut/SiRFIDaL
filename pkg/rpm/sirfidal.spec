Name:	sirfidal
Version:
Release:	0
Summary:	SiRFIDal - Simple RFID authentication for Linux
License:	GPL-3.0

Requires:	python3 >= 3.5, python3-psutil, python3-filelock, python3-setproctitle, python3-pyscard, python3-pyserial, python3-evdev, python3-cryptography, python3-pyperclip, python3-xlib, python3-tkinter, pcsc-lite, pcsc-tools, adb, sox


%description
SiRFIDal - Simple RFID authentication for Linux


%post
SERVER_CONFIG=/etc/sirfidal_server_parameters.py
CLIENT_CONFIG=/etc/sirfidal_clients_parameters.py

# We reinstalled systemd unit files, so even though they may not have changed,
# tell systemd to reload them
systemctl daemon-reload

# If we find .rpmsave versions of the configuration files, advise the user
# to recheck them
for FILE in ${SERVER_CONFIG} ${CLIENT_CONFIG}; do

  if [ -f ${FILE}.rpmsave ]; then
    echo "${FILE}.rpmsave HAS BEEN FOUND. YOU PROBABLY WANT TO CHECK IF ${FILE} NEEDS REINSTALLING!"
  fi

done


%preun
# Are we being called to remove the package?
if [ "$1" = 0 ]; then

  # Stop and disable any running SiRFIDaL services
  systemctl disable --now sirfidal_beep
  systemctl disable --now sirfidal_auto_send_enter_at_login
  systemctl disable --now sirfidal_keyboard_wedge
  systemctl disable --now sirfidal_server

fi


%postun
# We may have removed or changed systemd unit files, so tell systemd to
# reload them
systemctl daemon-reload


%files
%doc /usr/share/doc/sirfidal/README
%doc /usr/share/doc/sirfidal/LICENSE

/usr/local/bin/sirfidal_server.py

/usr/local/bin/sirfidal_client_class.py

/usr/local/bin/sirfidal_autolockscreen.py
/usr/local/bin/sirfidal_auto_send_enter_at_login.py
/usr/local/bin/sirfidal_autotype.py
/usr/local/bin/sirfidal_beep.py
/usr/local/bin/sirfidal_getuids.py
/usr/local/bin/sirfidal_keyboard_wedge.py
/usr/local/bin/sirfidal_pam.py
/usr/local/bin/sirfidal_useradm.py

%config /etc/sirfidal_server_parameters.py
%config /etc/sirfidal_clients_parameters.py

%config /usr/share/pam-configs/sirfidal_pam.config

/lib/systemd/system/sirfidal_auto_send_enter_at_login.service
/lib/systemd/system/sirfidal_beep.service
/lib/systemd/system/sirfidal_keyboard_wedge.service
/lib/systemd/system/sirfidal_server.service

/etc/xdg/autostart/sirfidal_autolockscreen.desktop
/etc/xdg/autostart/sirfidal_autotype.desktop

/usr/local/share/sounds/sirfidal/down.wav
/usr/local/share/sounds/sirfidal/up.wav
