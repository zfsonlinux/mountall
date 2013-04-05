# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([mountall], [2.49], [ubuntu-devel@lists.ubuntu.com])
AC_COPYRIGHT([[Copyright © 201-2012 Canonical Ltd.]])
AC_CONFIG_SRCDIR([util/mntctl.c])
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE

AM_INIT_AUTOMAKE([1.11 foreign nostdinc color-tests silent-rules])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])

LT_PREREQ(2.2.4)
LT_INIT

AM_GNU_GETTEXT_VERSION([0.17])
AM_GNU_GETTEXT()

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PATH_PROG([NIH_DBUS_TOOL], [nih-dbus-tool])
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES([NIH], [libnih >= 1.0.0])
PKG_CHECK_MODULES([NIH_DBUS], [libnih-dbus >= 1.0.0])
PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.2.16])
PKG_CHECK_MODULES([UDEV], [libudev >= 146])
PKG_CHECK_MODULES([PLYMOUTH], [ply-boot-client >= 0.8.0])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_PROG_CC_C99
AC_SYS_LARGEFILE

# Checks for library functions.

# Other checks
NIH_COMPILER_WARNINGS
NIH_COMPILER_OPTIMISATIONS
NIH_COMPILER_COVERAGE

NIH_LINKER_OPTIMISATIONS


AC_CONFIG_FILES([ Makefile intl/Makefile apport/Makefile
		  dbus/Makefile src/Makefile conf/Makefile
		  util/Makefile man/Makefile po/Makefile.in 
		  debian/initramfs/Makefile 
		  debian/initramfs/upstart-jobs/Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
