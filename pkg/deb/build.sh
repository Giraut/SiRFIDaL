#!/bin/sh

# Directories and files
BUILDSCRIPTPATH=$(realpath "$0")
BUILDSCRIPTDIR=$(dirname ${BUILDSCRIPTPATH})
SRC=$(realpath ${BUILDSCRIPTDIR}/../..)
PKGSRC=${BUILDSCRIPTDIR}/sirfidal
VERSION=$(grep -E "^ +v[0-9]+\.[0-9]+\.[0-9]+ *$" ${SRC}/README | sed -E 's/[ v]*//')
PKGBUILD=${PKGSRC}-${VERSION}-0_all
PKG=${PKGBUILD}.deb

# Create a fresh skeleton package build directory
rm -rf ${PKGBUILD}
cp -a ${PKGSRC} ${PKGBUILD}

# Create empty directory structure
mkdir -p ${PKGBUILD}/etc/xdg/autostart
mkdir -p ${PKGBUILD}/lib/systemd/system
mkdir -p ${PKGBUILD}/usr/share/pam-configs
mkdir -p ${PKGBUILD}/usr/local/bin
mkdir -p ${PKGBUILD}/usr/local/share/sounds/sirfidal

# Populate the package build directory with the source files
install -m 644 ${SRC}/README ${PKGBUILD}/usr/share/doc/sirfidal
install -m 644 ${SRC}/README.example_PAM_scenarios ${PKGBUILD}/usr/share/doc/sirfidal
install -m 644 ${SRC}/README.security ${PKGBUILD}/usr/share/doc/sirfidal
install -m 644 ${SRC}/LICENSE ${PKGBUILD}/usr/share/doc/sirfidal

install -m 755 ${SRC}/sirfidal_server.py ${PKGBUILD}/usr/local/bin

install -m 644 ${SRC}/sirfidal_client_class.py ${PKGBUILD}/usr/local/bin

install -m 755 ${SRC}/sirfidal_autolockscreen.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_auto_send_enter_at_login.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_autotype.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_beep.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_getuids.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_keyboard_wedge.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_pam.py ${PKGBUILD}/usr/local/bin
install -m 755 ${SRC}/sirfidal_useradm.py ${PKGBUILD}/usr/local/bin

install -m 600 ${SRC}/sirfidal_server_parameters.py ${PKGBUILD}/etc
install -m 644 ${SRC}/sirfidal_clients_parameters.py ${PKGBUILD}/etc

install -m 644 ${SRC}/sirfidal_pam.config ${PKGBUILD}/usr/share/pam-configs

install -m 644 ${SRC}/*.service ${PKGBUILD}/lib/systemd/system
install -m 644 ${SRC}/*.desktop ${PKGBUILD}/etc/xdg/autostart

install -m 644 ${SRC}/sounds/* ${PKGBUILD}/usr/local/share/sounds/sirfidal

# Set the version in the control file
sed -i "s/^Version:.*\$/Version: ${VERSION}/" ${PKGBUILD}/DEBIAN/control

# Fixup permissions
find ${PKGBUILD} -type d -exec chmod 755 {} \;
chmod 644 ${PKGBUILD}/DEBIAN/conffiles
chmod 644 ${PKGBUILD}/DEBIAN/control
chmod 755 ${PKGBUILD}/DEBIAN/postinst
chmod 755 ${PKGBUILD}/DEBIAN/postrm
chmod 755 ${PKGBUILD}/DEBIAN/preinst
chmod 755 ${PKGBUILD}/DEBIAN/prerm
chmod 644 ${PKGBUILD}/usr/share/doc/sirfidal/copyright

# Build the .deb package
fakeroot dpkg -b ${PKGBUILD} ${PKG}
