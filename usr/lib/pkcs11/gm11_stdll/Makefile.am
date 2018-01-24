# Makefile.am for GM11 token for openCryptoki
#
nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_gm11.la

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_gm11_la_CFLAGS = -DDEV -D_THREAD_SAFE            \
					    -DSHALLOW=0 -DEPSWTOK=1 -DLITE=0  \
					    -DNOCDMF -DNOMD2 -DNORIPE         \
					    -fPIC -O0 -DDEFENSIVE_MECHLIST 		    \
					    -I/usr/include -I.		    \
					    -I../../../include/pkcs11/stdll \
					    -I../../../include/pkcs11	    \
					    -I../common -DSTDLL_NAME=\"gm11tok\"

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_gm11_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					     -lc -lpthread -lcrypto -lrt -llber -ldl

opencryptoki_stdll_libpkcs11_gm11_la_SOURCES = ../common/asn1.c		\
					     ../common/lock_btree.c		\
					     ../common/cert.c		\
					     ../common/hwf_obj.c	\
					     ../common/dp_obj.c		\
					     ../common/data_obj.c	\
					     ../common/dig_mgr.c	\
					     ../common/encr_mgr.c	\
					     ../common/decr_mgr.c	\
					     ../common/globals.c	\
					     ../common/loadsave.c	\
					     ../common/mech_aes.c       \
                         ../common/mech_des.c       \
                         ../common/mech_des3.c      \
					     ../common/mech_ec.c	\
					     ../common/mech_md5.c	\
					     ../common/mech_md2.c	\
					     ../common/mech_rng.c	\
					     ../common/mech_rsa.c       \
					     ../common/mech_sha.c	\
					     ../common/mech_dsa.c	\
					     ../common/mech_dh.c	\
					     ../common/mech_ssl3.c      \
					     ../common/obj_mgr.c	\
					     ../common/object.c		\
					     ../common/lock_sess_mgr.c	\
					     ../common/sign_mgr.c	\
					     ../common/verify_mgr.c	\
					     ../common/key.c		\
					     ../common/key_mgr.c        \
					     ../common/template.c	\
					     ../common/p11util.c	\
					     ../common/utility.c	\
					     ../common/trace.c		\
					     ../common/mech_list.c	\
					     ../common/shared_memory.c	\
					     ../common/attributes.c     \
					     ../common/sw_crypt.c       \
					     new_host.c			\
					     gm11_specific.c

else
opencryptoki_stdll_libpkcs11_gm11_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					     -lc -lpthread -litm -lcrypto -lrt -llber -ldl

opencryptoki_stdll_libpkcs11_gm11_la_SOURCES = ../common/asn1.c		\
					     ../common/btree.c		\
					     ../common/cert.c		\
					     ../common/hwf_obj.c	\
					     ../common/dp_obj.c		\
					     ../common/data_obj.c	\
					     ../common/dig_mgr.c	\
					     ../common/encr_mgr.c	\
					     ../common/decr_mgr.c	\
					     ../common/globals.c	\
					     ../common/loadsave.c	\
					     ../common/mech_aes.c       \
                         ../common/mech_des.c       \
                         ../common/mech_des3.c      \
					     ../common/mech_ec.c	\
					     ../common/mech_md5.c	\
					     ../common/mech_md2.c	\
					     ../common/mech_rng.c	\
					     ../common/mech_rsa.c       \
					     ../common/mech_sha.c	\
					     ../common/mech_dsa.c	\
					     ../common/mech_dh.c	\
					     ../common/mech_ssl3.c      \
					     ../common/obj_mgr.c	\
					     ../common/object.c		\
					     ../common/sess_mgr.c	\
					     ../common/sign_mgr.c	\
					     ../common/verify_mgr.c	\
					     ../common/key.c		\
					     ../common/key_mgr.c        \
					     ../common/template.c	\
					     ../common/p11util.c	\
					     ../common/utility.c	\
					     ../common/trace.c		\
					     ../common/mech_list.c	\
					     ../common/shared_memory.c	\
					     ../common/attributes.c     \
					     ../common/sw_crypt.c       \
					     new_host.c			\
					     gm11_specific.c
endif

noinst_HEADERS = gm11.h

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_gm11.so PKCS11_GM11.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/gm11tok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/gm11tok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/gm11tok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/gm11tok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/gm11tok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/gm11tok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/gm11tok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/gm11tok

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_GM11.so; fi

install-data-local :
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/gm11tok.conf || $(INSTALL) -m 644 $(srcdir)/gm11tok.conf $(DESTDIR)$(sysconfdir)/opencryptoki/gm11tok.conf || true
