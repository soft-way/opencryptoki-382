#!/usr/bin/env bash
 
set -eux
 
PACKAGES="
findutils
gcc
openssl-devel
rpm-build
make
"
yum -y install ${PACKAGES}

mkdir -p ~/rpmbuild/SOURCES

cd /opencryptoki
tar -cf ~/rpmbuild/SOURCES/pencryptoki-3.8.2.tar *
gzip ~/rpmbuild/SOURCES/pencryptoki-3.8.2.tar
rpmbuild -bb rpm/opencryptoki.spec
