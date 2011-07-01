## Process this file with automake to produce Makefile.in

AM_CFLAGS = \
	$(NIH_CFLAGS) \
	$(NIH_DBUS_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(PLYMOUTH_CFLAGS)

AM_CPPFLAGS = \
	-DLOCALEDIR="\"$(localedir)\"" \
	-I$(top_builddir) -I$(top_srcdir) -iquote$(builddir) -iquote$(srcdir) \
	-I$(top_srcdir)/intl


initdir = $(libdir)/init
dist_init_DATA = fstab


sbin_PROGRAMS = \
	mountall

mountall_SOURCES = \
	control.c control.h mountall.c

nodist_mountall_SOURCES = \
	$(com_ubuntu_Upstart_OUTPUTS) \
	$(com_ubuntu_Mountall_Server_OUTPUTS)


mountall_LDADD = \
	$(NIH_LIBS) \
	$(NIH_DBUS_LIBS) \
	$(DBUS_LIBS) \
	$(UDEV_LIBS) \
	$(PLYMOUTH_LIBS) \
	$(LTLIBINTL)

com_ubuntu_Upstart_OUTPUTS = \
	com.ubuntu.Upstart.c \
	com.ubuntu.Upstart.h

com_ubuntu_Upstart_XML = \
	../dbus/com.ubuntu.Upstart.xml

$(com_ubuntu_Upstart_OUTPUTS): $(com_ubuntu_Upstart_XML)
	$(NIH_DBUS_TOOL) \
		--package=$(PACKAGE) \
		--mode=proxy --prefix=upstart \
		--default-interface=com.ubuntu.Upstart0_6 \
		--output=$@ $<

com_ubuntu_Mountall_Server_OUTPUTS = \
	com.ubuntu.Mountall.Server.c \
	com.ubuntu.Mountall.Server.h

com_ubuntu_Mountall_Server_XML = \
	../dbus/com.ubuntu.Mountall.Server.xml

$(com_ubuntu_Mountall_Server_OUTPUTS): $(com_ubuntu_Mountall_Server_XML)
	$(NIH_DBUS_TOOL) \
		--package=$(PACKAGE) \
		--mode=object --prefix=control \
		--default-interface=com.ubuntu.Mountall0_1.Server \
		--output=$@ $<


# These have to be built sources because we can't compile object files
# without the header file existing first
BUILT_SOURCES = \
	$(com_ubuntu_Upstart_OUTPUTS) \
	$(com_ubuntu_Mountall_Server_OUTPUTS)

CLEANFILES = \
	$(com_ubuntu_Upstart_OUTPUTS) \
	$(com_ubuntu_Mountall_Server_OUTPUTS)


clean-local:
	rm -f *.gcno *.gcda

maintainer-clean-local:
	rm -f *.gcov
