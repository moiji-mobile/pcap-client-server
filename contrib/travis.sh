#!/usr/bin/env bash

set -ex

rm -rf deps/install
mkdir deps || true
cd deps
git clone git://git.osmocom.org/libosmocore

cd libosmocore
git reset --hard 460f9ef7da1db11b104fdfe635ebcbd8a071f205
autoreconf --install --force
./configure --prefix=$PWD/../install
make -j 4 install

cd ../../
autoreconf --install --force
PCAP_LIBS="-lpcap" PCAP_CFLAGS="" PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig ./configure --with-pcap-config=/bin/true
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig make -j 4
DISTCHECK_CONFIGURE_FLAGS="--with-pcap-config=/bin/true" PCAP_LIBS="-lpcap" PCAP_CFLAGS="" PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig LD_LIBRARY_PATH=$PWD/deps/install/lib make distcheck
