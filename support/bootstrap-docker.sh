#!/usr/bin/env bash
 
set -eux

# set bintray repository
ls /etc/yum.repos.d/
echo "[bintray--softway-rpm]
name=bintray--softway-rpm
baseurl=https://dl.bintray.com/softway/rpm/7/x86_64
gpgcheck=0
repo_gpgcheck=0
enabled=1" > /etc/yum.repos.d/bintray-softway-rpm.repo

PACKAGES="
findutils
gcc
openssl-devel
rpm-build
make
trousers-devel
openldap-devel
autoconf
automake
libtool
bison
flex
libitm-devel
gmssl-devel
"
for p in `echo ${PACKAGES}`; do
    yum -y install $p
done

mkdir -p ~/rpmbuild/SOURCES

cd /opencryptoki
tar -cf ~/rpmbuild/SOURCES/opencryptoki-3.8.2.tar *
gzip ~/rpmbuild/SOURCES/opencryptoki-3.8.2.tar
rpmbuild -bb rpm/opencryptoki.spec
