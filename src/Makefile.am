## Process this file with automake to produce Makefile.in

AM_CFLAGS = \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS)

AM_CPPFLAGS = \
	-DLOCALEDIR="\"$(localedir)\"" \
	-I$(top_builddir) -I$(top_srcdir) -iquote$(builddir) -iquote$(srcdir) \
	-I$(top_srcdir)/intl


sbin_PROGRAMS = \
	mountall

mountall_SOURCES = \
	mountall.c
nodist_mountall_SOURCES = \
	$(com_ubuntu_Upstart_OUTPUTS)
mountall_LDADD = \
	../nih/libnih.la \
	../nih-dbus/libnih-dbus.la \
	$(LTLIBINTL) \
	$(DBUS_LIBS) \
	$(UDEV_LIBS)


com_ubuntu_Upstart_OUTPUTS = \
	com.ubuntu.Upstart.c \
	com.ubuntu.Upstart.h

com_ubuntu_Upstart_XML = \
	../dbus/com.ubuntu.Upstart.xml

$(com_ubuntu_Upstart_OUTPUTS): $(com_ubuntu_Upstart_XML) $(top_builddir)/nih-dbus-tool/nih-dbus-tool
	$(top_builddir)/nih-dbus-tool/nih-dbus-tool \
		--mode=proxy --prefix=upstart --default-interface=com.ubuntu.Upstart0_6 \
		--output=$@ $<


# These have to be built sources because we can't compile object files
# without the header file existing first
BUILT_SOURCES = \
	$(com_ubuntu_Upstart_OUTPUTS)

CLEANFILES = \
	$(com_ubuntu_Upstart_OUTPUTS)


clean-local:
	rm -f *.gcno *.gcda

maintainer-clean-local:
	rm -f *.gcov
