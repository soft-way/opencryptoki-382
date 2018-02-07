#!/usr/bin/env bash
 
set -eux
 
PACKAGES="
findutils
gcc
openssl-devel
rpm-build
make
"
for p in `echo ${PACKAGES}`; do
    yum -y install $p
done

mkdir -p ~/rpmbuild/SOURCES

cd /opencryptoki
tar -cf ~/rpmbuild/SOURCES/opencryptoki-3.8.2.tar *
gzip ~/rpmbuild/SOURCES/opencryptoki-3.8.2.tar
rpmbuild -bb rpm/opencryptoki.spec
