#!/bin/sh

# Directories and files
BUILDSCRIPTPATH=$(realpath "$0")
BUILDSCRIPTDIR=$(dirname ${BUILDSCRIPTPATH})
SRC=$(realpath ${BUILDSCRIPTDIR}/../..)
VERSION=$(grep -E "^ +v[0-9]+\.[0-9]+\.[0-9]+ *$" ${SRC}/README | sed -E 's/[ v]*//')
PKGSPEC=${BUILDSCRIPTDIR}/sirfidal.spec
PKG=sirfidal-${VERSION}-0.noarch
PKGBUILD=${BUILDSCRIPTDIR}/${PKG}
BUILDROOT=${PKGBUILD}/BUILDROOT/${PKG}
RPMDIR=${PKGBUILD}/RPMS

# Create a fresh RPM build directory
rm -rf ${PKGBUILD}
mkdir -p ${PKGBUILD}/SPECS
mkdir -p ${PKGBUILD}/SOURCES
mkdir -p ${PKGBUILD}/BUILD
mkdir -p ${PKGBUILD}/BUILDROOT
mkdir -p ${PKGBUILD}/RPMS
mkdir -p ${PKGBUILD}/SRPMS

# Copy the spec file into the RPM build directory
cp -a ${PKGSPEC} ${PKGBUILD}/SPECS

# Create empty directory structure
mkdir -p ${BUILDROOT}/etc/xdg/autostart
mkdir -p ${BUILDROOT}/lib/systemd/system
mkdir -p ${BUILDROOT}/usr/share/pam-configs
mkdir -p ${BUILDROOT}/usr/local/bin
mkdir -p ${BUILDROOT}/usr/local/share/sounds/sirfidal
mkdir -p ${BUILDROOT}/usr/share/doc/sirfidal

# Populate the package build directory with the source files
install -m 644 ${SRC}/README ${BUILDROOT}/usr/share/doc/sirfidal
install -m 644 ${SRC}/LICENSE ${BUILDROOT}/usr/share/doc/sirfidal

install -m 755 ${SRC}/sirfidal_server.py ${BUILDROOT}/usr/local/bin

install -m 644 ${SRC}/sirfidal_client_class.py ${BUILDROOT}/usr/local/bin

install -m 755 ${SRC}/sirfidal_autolockscreen.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_auto_send_enter_at_login.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_autotype.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_beep.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_getuids.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_keyboard_wedge.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_pam.py ${BUILDROOT}/usr/local/bin
install -m 755 ${SRC}/sirfidal_useradm.py ${BUILDROOT}/usr/local/bin

install -m 600 ${SRC}/sirfidal_server_parameters.py ${BUILDROOT}/etc
install -m 644 ${SRC}/sirfidal_clients_parameters.py ${BUILDROOT}/etc

install -m 644 ${SRC}/sirfidal_pam.config ${BUILDROOT}/usr/share/pam-configs

install -m 644 ${SRC}/*.service ${BUILDROOT}/lib/systemd/system
install -m 644 ${SRC}/*.desktop ${BUILDROOT}/etc/xdg/autostart

install -m 644 ${SRC}/sounds/* ${BUILDROOT}/usr/local/share/sounds/sirfidal

# Fixup permissions
find ${PKGBUILD} -type d -exec chmod 755 {} \;
chmod 644 ${PKGBUILD}/SPECS/sirfidal.spec

# Set the version in the spec file
sed -i "s/^Version:.*\$/Version: ${VERSION}/" ${PKGBUILD}/SPECS/sirfidal.spec

# Build the .rpm package
rpmbuild --target=noarch --define "_topdir ${PKGBUILD}" --define "_rpmdir ${RPMDIR}" -bb ${PKGBUILD}/SPECS/sirfidal.spec

# Retrieve the built .rpm package
cp ${RPMDIR}/noarch/${PKG}.rpm ${BUILDSCRIPTDIR}
