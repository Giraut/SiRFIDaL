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
cp -a ${SRC}/README ${PKGBUILD}/usr/share/doc/sirfidal
cp -a ${SRC}/LICENSE ${PKGBUILD}/usr/share/doc/sirfidal

cp -a ${SRC}/sirfidal_server.py ${PKGBUILD}/usr/local/bin

cp -a ${SRC}/sirfidal_client_class.py ${PKGBUILD}/usr/local/bin

cp -a ${SRC}/sirfidal_autolockscreen.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_auto_send_enter_at_login.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_autotype.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_beep.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_getuids.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_keyboard_wedge.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_pam.py ${PKGBUILD}/usr/local/bin
cp -a ${SRC}/sirfidal_useradm.py ${PKGBUILD}/usr/local/bin

cp -a ${SRC}/sirfidal_server_parameters.py ${PKGBUILD}/etc
cp -a ${SRC}/sirfidal_clients_parameters.py ${PKGBUILD}/etc

cp -a ${SRC}/sirfidal_pam.config ${PKGBUILD}/usr/share/pam-configs

cp -a ${SRC}/*.service ${PKGBUILD}/lib/systemd/system
cp -a ${SRC}/*.desktop ${PKGBUILD}/etc/xdg/autostart

cp -a ${SRC}/sounds/* ${PKGBUILD}/usr/local/share/sounds/sirfidal

# Set the version in the control file
sed -i "s/^Version:.*\$/Version: ${VERSION}/" ${PKGBUILD}/DEBIAN/control

# Build the .deb package
fakeroot dpkg -b ${PKGBUILD} ${PKG}
