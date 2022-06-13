AC_PREREQ([2.69])
AC_INIT([openssl-md5-mb], [1.0], [guodong.xu@linaro.org])
AC_CONFIG_SRCDIR([src/e_md5_mb.c])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

AC_CHECK_HEADERS([openssl/engine.h])

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
