ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES=md5_mb.la

md5_mb_la_SOURCES=e_md5_mb.c \
		md5_mb_sw_isal_crypto_inf.c \
		md5_mb_sw_md5.c
md5_mb_la_LIBADD=-lpthread -lisal_crypto
md5_mb_la_LDFLAGS=-module

AUTOMAKE_OPTIONS = subdir-objects