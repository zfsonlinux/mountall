## Process this file with automake to produce Makefile.in

AM_CFLAGS = \
	$(NIH_CFLAGS) \
	$(NIH_DBUS_CFLAGS) \
	$(DBUS_CFLAGS)

AM_CPPFLAGS = \
	-DLOCALEDIR="\"$(localedir)\"" \
	-DSBINDIR="\"$(sbindir)\"" \
	-I$(top_builddir) -I$(top_srcdir) -iquote$(builddir) -iquote$(srcdir) \
	-I$(top_srcdir)/intl

sbin_PROGRAMS = \
		mntctl

mntctl_SOURCES = \
		 mntctl.c mntctl.h

nodist_mntctl_SOURCES = \
	$(com_ubuntu_Mountall_Server_OUTPUTS) 
mntctl_LDADD = \
	$(LTLIBINTL) \
	$(NIH_LIBS) \
	$(NIH_DBUS_LIBS) \
	$(DBUS_LIBS)

com_ubuntu_Mountall_Server_OUTPUTS = \
	com.ubuntu.Mountall.Server.c \
	com.ubuntu.Mountall.Server.h

com_ubuntu_Mountall_Server_XML = \
	../dbus/com.ubuntu.Mountall.Server.xml

$(com_ubuntu_Mountall_Server_OUTPUTS): $(com_ubuntu_Mountall_Server_XML)
	$(AM_V_GEN)$(NIH_DBUS_TOOL) \
		--package=$(PACKAGE) \
		--mode=proxy --prefix=mountall_server \
		--default-interface=com.ubuntu.Mountall0_1.Server \
		--output=$@ $<

# These have to be built sources because we can't compile object files
# without the header file existing first
BUILT_SOURCES = \
	$(com_ubuntu_Mountall_Server_OUTPUTS) 

CLEANFILES = \
	$(com_ubuntu_Mountall_Server_OUTPUTS) 

.PHONY: 

clean-local:
	rm -f *.gcno *.gcda

maintainer-clean-local:
	rm -f *.gcov
