#!/usr/bin/env bash
 
set -eux

OCK_VERSION=3.8.2

# set bintray repository
ls /etc/yum.repos.d/
echo "[bintray--softway-rpm]
name=bintray--softway-rpm
baseurl=https://dl.bintray.com/softway/rpm/7/x86_64
gpgcheck=0
repo_gpgcheck=0
enabled=1" > /etc/yum.repos.d/bintray-softway-rpm.repo
ls /etc/yum.repos.d/

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

cd /
tar -cf ~/rpmbuild/SOURCES/opencryptoki-${OCK_VERSION}.tar opencryptoki-${OCK_VERSION}
gzip ~/rpmbuild/SOURCES/opencryptoki-${OCK_VERSION}.tar
rpmbuild -bb /opencryptoki-${OCK_VERSION}/rpm/opencryptoki.spec

ls -l ~/rpmbuild/RPMS/x86_64/

echo "End"
