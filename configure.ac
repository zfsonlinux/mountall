# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([mountall], [0.2], [ubuntu-devel@lists.ubuntu.com])
AC_COPYRIGHT([[Copyright © 2009 Canonical Ltd.]])
AC_CONFIG_SRCDIR([src/mountall.c])
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE

AM_INIT_AUTOMAKE([1.10 foreign nostdinc])

LT_PREREQ(2.2.4)
LT_INIT

AM_GNU_GETTEXT_VERSION([0.16.1])
AM_GNU_GETTEXT()

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

# Checks for libraries.
NIH_INIT([dbus])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_SYS_LARGEFILE

# Checks for library functions.

# Other checks
PKG_CHECK_MODULES([UDEV], [libudev >= 146])


AC_CONFIG_FILES([ Makefile m4/Makefile intl/Makefile
		  nih/Makefile nih-dbus/Makefile nih-dbus-tool/Makefile
		  dbus/Makefile src/Makefile conf/Makefile
		  man/Makefile po/Makefile.in ])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
